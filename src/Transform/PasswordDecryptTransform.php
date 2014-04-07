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
use Eloquent\Lockbox\Comparator\SlowStringComparator;
use Eloquent\Lockbox\Key\KeyDeriver;
use Eloquent\Lockbox\Key\KeyDeriverInterface;
use Eloquent\Lockbox\Padding\PkcsPadding;
use Eloquent\Lockbox\Padding\UnpadderInterface;
use Eloquent\Lockbox\Result\DecryptionResultInterface;
use Eloquent\Lockbox\Result\DecryptionResultType;
use Eloquent\Lockbox\Result\PasswordDecryptionResult;

/**
 * A data transform for decryption of streaming data with a password.
 */
class PasswordDecryptTransform extends AbstractTransform implements
    DecryptTransformInterface
{
    /**
     * Construct a new password decrypt data transform.
     *
     * @param string                   $password   The password to decrypt with.
     * @param KeyDeriverInterface|null $keyDeriver The key deriver to use.
     * @param UnpadderInterface|null   $unpadder   The unpadder to use.
     */
    public function __construct(
        $password,
        KeyDeriverInterface $keyDeriver = null,
        UnpadderInterface $unpadder = null
    ) {
        if (null === $keyDeriver) {
            $keyDeriver = KeyDeriver::instance();
        }
        if (null === $unpadder) {
            $unpadder = PkcsPadding::instance();
        }

        $this->password = $password;
        $this->keyDeriver = $keyDeriver;
        $this->unpadder = $unpadder;
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
     * Get the unpadder.
     *
     * @return UnpadderInterface The unpadder.
     */
    public function unpadder()
    {
        return $this->unpadder;
    }

    /**
     * Get the decryption result.
     *
     * @return DecryptionResultInterface|null The decryption result, or null if not yet known.
     */
    public function result()
    {
        return $this->result;
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
     * @return tuple<string,integer,mixed> A 3-tuple of the transformed data, the number of bytes consumed, and any resulting error.
     */
    public function transform($data, &$context, $isEnd = false)
    {
        if ($this->result) {
            return array('', 0, null);
        }

        if (null === $context) {
            $context = $this->initializeContext();
        }

        $dataSize = strlen($data);
        $consumed = 0;

        if (!$context->isVersionSeen) {
            if ($dataSize < 1) {
                if ($isEnd) {
                    $this->result = new PasswordDecryptionResult(
                        DecryptionResultType::INSUFFICIENT_DATA()
                    );
                    $this->finalizeContext($context);

                    return array('', $consumed, $this->result);
                }

                return array('', $consumed, null);
            }

            $context->isVersionSeen = true;

            $versionData = substr($data, 0, 1);
            $version = ord($versionData);
            if (1 !== $version) {
                $this->result = new PasswordDecryptionResult(
                    DecryptionResultType::UNSUPPORTED_VERSION()
                );
                $this->finalizeContext($context);

                return array('', 1, $this->result);
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
                    $this->result = new PasswordDecryptionResult(
                        DecryptionResultType::INSUFFICIENT_DATA()
                    );
                    $this->finalizeContext($context);

                    return array('', $consumed, $this->result);
                }

                return array('', $consumed, null);
            }

            $context->isTypeSeen = true;

            $typeData = substr($data, 0, 1);
            $type = ord($typeData);
            if (2 !== $type) {
                $this->result = new PasswordDecryptionResult(
                    DecryptionResultType::UNSUPPORTED_TYPE()
                );
                $this->finalizeContext($context);

                return array('', 1, $this->result);
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
                    $this->result = new PasswordDecryptionResult(
                        DecryptionResultType::INSUFFICIENT_DATA()
                    );
                    $this->finalizeContext($context);

                    return array('', $consumed, $this->result);
                }

                return array('', $consumed, null);
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
                    $this->result = new PasswordDecryptionResult(
                        DecryptionResultType::INSUFFICIENT_DATA()
                    );
                    $this->finalizeContext($context);

                    return array('', $consumed, $this->result);
                }

                return array('', $consumed, null);
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
                    $this->result = new PasswordDecryptionResult(
                        DecryptionResultType::INSUFFICIENT_DATA()
                    );
                    $this->finalizeContext($context);

                    return array('', $consumed, $this->result);
                }

                return array('', $consumed, null);
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
                $this->result = new PasswordDecryptionResult(
                    DecryptionResultType::INSUFFICIENT_DATA()
                );
                $this->finalizeContext($context);

                return array('', $consumed, $this->result);
            }

            return array('', $consumed, null);
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
            if (
                !SlowStringComparator::isEqual(
                    hash_final($context->hashContext, true),
                    $hash
                )
            ) {
                $this->result = new PasswordDecryptionResult(
                    DecryptionResultType::INVALID_MAC()
                );
                $this->finalizeContext($context);

                return array('', $consumed, $this->result);
            }
        }

        $output = mdecrypt_generic($context->mcryptModule, $consumedData);

        if ($isEnd) {
            list($isSuccessful, $output) = $this->unpadder()->unpad($output);

            if ($isSuccessful) {
                $this->result = new PasswordDecryptionResult(
                    DecryptionResultType::SUCCESS(),
                    null,
                    $context->iterations
                );
                $this->finalizeContext($context);
            } else {
                $this->result = new PasswordDecryptionResult(
                    DecryptionResultType::INVALID_PADDING()
                );
                $this->finalizeContext($context);

                return array('', $consumed, $this->result);
            }
        }

        return array($output, $consumed, null);
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
    private $unpadder;
    private $result;
}
