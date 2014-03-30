<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Transform;

use Eloquent\Confetti\AbstractTransform;
use Eloquent\Lockbox\Exception\PasswordDecryptionFailedException;
use Eloquent\Lockbox\Key\KeyDeriver;
use Eloquent\Lockbox\Key\KeyDeriverInterface;
use Exception;

/**
 * A data transform for decryption of streaming data with a password.
 */
class PasswordDecryptTransform extends AbstractTransform
{
    /**
     * Construct a new password decrypt data transform.
     *
     * @param string                   $password   The password to decrypt with.
     * @param KeyDeriverInterface|null $keyDeriver The key deriver to use.
     */
    public function __construct(
        $password,
        KeyDeriverInterface $keyDeriver = null
    ) {
        if (null === $keyDeriver) {
            $keyDeriver = KeyDeriver::instance();
        }

        $this->password = $password;
        $this->keyDeriver = $keyDeriver;
    }

    /**
     * Get the password.
     *
     * @return string The password.
     */
    public function password()
    {
        return $this->password;
    }

    /**
     * Get the key deriver.
     *
     * @return KeyDeriverInterface The key deriver.
     */
    public function keyDeriver()
    {
        return $this->keyDeriver;
    }

    /**
     * Get the number of hash iterations used.
     *
     * @return integer|null The hash iterations, or null if not yet known.
     */
    public function iterations()
    {
        return $this->iterations;
    }

    /**
     * Transform the supplied data.
     *
     * This method may transform only part of the supplied data. The return
     * value includes information about how much data was actually consumed. The
     * transform can be forced to consume all data by passing a boolean true as
     * the $isEnd argument.
     *
     * The $context argument will initially be null, but any value assigned to
     * this variable will persist until the stream transformation is complete.
     * It can be used as a place to store state, such as a buffer.
     *
     * It is guaranteed that this method will be called with $isEnd = true once,
     * and only once, at the end of the stream transformation.
     *
     * @param string  $data     The data to transform.
     * @param mixed   &$context An arbitrary context value.
     * @param boolean $isEnd    True if all supplied data must be transformed.
     *
     * @return tuple<string,integer> A 2-tuple of the transformed data, and the number of bytes consumed.
     * @throws Exception             If the data cannot be transformed.
     */
    public function transform($data, &$context, $isEnd = false)
    {
        if (null === $context) {
            $context = $this->initializeContext();
        }

        $dataSize = strlen($data);
        $consumed = 0;

        if (!$context->isVersionSeen) {
            if ($dataSize < 1) {
                if ($isEnd) {
                    $this->finalizeContext($context);

                    throw new PasswordDecryptionFailedException(
                        $this->password()
                    );
                }

                return array('', $consumed);
            }

            $context->isVersionSeen = true;

            $versionData = substr($data, 0, 1);
            $version = ord($versionData);
            if (1 !== $version) {
                $this->finalizeContext($context);

                throw new PasswordDecryptionFailedException(
                    $this->password(),
                    new UnsupportedVersionException($version)
                );
            }

            $context->hashBuffer .= $versionData;

            if (1 === $dataSize) {
                $data = '';
            } else {
                $data = substr($data, 1);
            }

            $dataSize -= 1;
            $consumed += 1;
        }

        if (!$context->isTypeSeen) {
            if ($dataSize < 1) {
                if ($isEnd) {
                    $this->finalizeContext($context);

                    throw new PasswordDecryptionFailedException(
                        $this->password()
                    );
                }

                return array('', $consumed);
            }

            $context->isTypeSeen = true;

            $typeData = substr($data, 0, 1);
            $type = ord($typeData);
            if (2 !== $type) {
                $this->finalizeContext($context);

                throw new PasswordDecryptionFailedException(
                    $this->password(),
                    new UnsupportedTypeException($type)
                );
            }

            $context->hashBuffer .= $typeData;

            if (1 === $dataSize) {
                $data = '';
            } else {
                $data = substr($data, 1);
            }

            $dataSize -= 1;
            $consumed += 1;
        }

        if (null === $context->iterations) {
            if ($dataSize < 4) {
                if ($isEnd) {
                    $this->finalizeContext($context);

                    throw new PasswordDecryptionFailedException(
                        $this->password()
                    );
                }

                return array('', $consumed);
            }

            $context->isIterationsSeen = true;

            $iterationsData = substr($data, 0, 4);
            $iterations = unpack('N', $iterationsData);
            $context->iterations = array_shift($iterations);

            $context->hashBuffer .= $iterationsData;

            if (4 === $dataSize) {
                $data = '';
            } else {
                $data = substr($data, 4);
            }

            $dataSize -= 4;
            $consumed += 4;
        }

        if (null === $context->key) {
            if ($dataSize < 64) {
                if ($isEnd) {
                    $this->finalizeContext($context);

                    throw new PasswordDecryptionFailedException(
                        $this->password()
                    );
                }

                return array('', $consumed);
            }

            $salt = substr($data, 0, 64);
            list($context->key) = $this->keyDeriver()->deriveKeyFromPassword(
                $this->password(),
                $context->iterations,
                $salt
            );
            $context->hashContext = hash_init(
                'sha256',
                HASH_HMAC,
                $context->key->authenticationSecret()
            );

            $context->hashBuffer .= $salt;

            if (64 === $dataSize) {
                $data = '';
            } else {
                $data = substr($data, 64);
            }

            $dataSize -= 64;
            $consumed += 64;
        }

        if (!$context->isInitialized) {
            if ($dataSize < 16) {
                if ($isEnd) {
                    $this->finalizeContext($context);

                    throw new PasswordDecryptionFailedException(
                        $this->password()
                    );
                }

                return array('', $consumed);
            }

            $iv = substr($data, 0, 16);
            mcrypt_generic_init(
                $context->mcryptModule,
                $context->key->encryptionSecret(),
                $iv
            );

            $context->hashBuffer .= $iv;
            $context->isInitialized = true;

            if (16 === $dataSize) {
                $data = '';
            } else {
                $data = substr($data, 16);
            }

            $dataSize -= 16;
            $consumed += 16;
        }

        if ($isEnd) {
            $requiredSize = 48;
        } else {
            $requiredSize = 64;
        }

        if ($dataSize < $requiredSize) {
            if ($isEnd) {
                $this->finalizeContext($context);

                throw new PasswordDecryptionFailedException($this->password());
            }

            return array('', $consumed);
        }

        if ($isEnd) {
            $consume = $dataSize - 32;
            $hash = substr($data, $consume);
            $consumedData = substr($data, 0, $consume);
            $consumed += $dataSize;
        } else {
            $consume = $this->blocksSize($dataSize - 48, 16, $isEnd);
            $consumed += $consume;
            $consumedData = substr($data, 0, $consume);
        }

        hash_update(
            $context->hashContext,
            $context->hashBuffer . $consumedData
        );
        $context->hashBuffer = '';

        if ($isEnd) {
            $context->isHashFinalized = true;
            if (hash_final($context->hashContext, true) !== $hash) {
                $this->finalizeContext($context);

                throw new PasswordDecryptionFailedException($this->password());
            }
        }

        $output = mdecrypt_generic($context->mcryptModule, $consumedData);

        if ($isEnd) {
            try {
                $output = $this->unpad($output);
            } catch (InvalidPaddingException $e) {
                $this->finalizeContext($context);

                throw new PasswordDecryptionFailedException(
                    $this->password(),
                    $e
                );
            }

            $this->iterations = $context->iterations;
            $this->finalizeContext($context);
        }

        return array($output, $consumed);
    }

    /**
     * Remove PKCS #7 (RFC 5652) padding from the supplied data.
     *
     * @link http://tools.ietf.org/html/rfc5652#section-6.3
     *
     * @param string $data The padded data.
     *
     * @return string                  The data with padding removed.
     * @throws InvalidPaddingException If the padding is invalid.
     */
    protected function unpad($data)
    {
        $padSize = ord(substr($data, -1));
        $padding = substr($data, -$padSize);

        if (str_repeat(chr($padSize), $padSize) !== $padding) {
            throw new InvalidPaddingException;
        }

        return substr($data, 0, -$padSize);
    }

    private function initializeContext()
    {
        $context = new PasswordDecryptTransformContext;

        $context->mcryptModule = mcrypt_module_open(
            MCRYPT_RIJNDAEL_128,
            '',
            MCRYPT_MODE_CBC,
            ''
        );

        return $context;
    }

    private function finalizeContext(PasswordDecryptTransformContext &$context)
    {
        if (null !== $context->mcryptModule) {
            if ($context->isInitialized) {
                mcrypt_generic_deinit($context->mcryptModule);
            }

            mcrypt_module_close($context->mcryptModule);
        }

        if (null !== $context->hashContext && !$context->isHashFinalized) {
            hash_final($context->hashContext);
        }

        $context = null;
    }

    private $password;
    private $keyDeriver;
    private $iterations;
}
