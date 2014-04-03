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
use Eloquent\Lockbox\Exception\DecryptionFailedException;
use Eloquent\Lockbox\Exception\UnsupportedTypeException;
use Eloquent\Lockbox\Exception\UnsupportedVersionException;
use Eloquent\Lockbox\Key\KeyInterface;
use Eloquent\Lockbox\Padding\Exception\InvalidPaddingException;
use Eloquent\Lockbox\Padding\PkcsPadding;
use Eloquent\Lockbox\Padding\UnpadderInterface;
use Exception;

/**
 * A data transform for decryption of streaming data.
 */
class DecryptTransform extends AbstractTransform
{
    /**
     * Construct a new decrypt data transform.
     *
     * @param KeyInterface           $key      The key to decrypt with.
     * @param UnpadderInterface|null $unpadder The unpadder to use.
     */
    public function __construct(
        KeyInterface $key,
        UnpadderInterface $unpadder = null
    ) {
        if (null === $unpadder) {
            $unpadder = PkcsPadding::instance();
        }

        $this->key = $key;
        $this->unpadder = $unpadder;
    }

    /**
     * Get the key.
     *
     * @return KeyInterface The key.
     */
    public function key()
    {
        return $this->key;
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

                    throw new DecryptionFailedException($this->key());
                }

                return array('', $consumed);
            }

            $context->isVersionSeen = true;

            $versionData = substr($data, 0, 1);
            $version = ord($versionData);
            if (1 !== $version) {
                $this->finalizeContext($context);

                throw new DecryptionFailedException(
                    $this->key(),
                    new UnsupportedVersionException($version)
                );
            }

            hash_update($context->hashContext, $versionData);

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

                    throw new DecryptionFailedException($this->key());
                }

                return array('', $consumed);
            }

            $context->isTypeSeen = true;

            $typeData = substr($data, 0, 1);
            $type = ord($typeData);
            if (1 !== $type) {
                $this->finalizeContext($context);

                throw new DecryptionFailedException(
                    $this->key(),
                    new UnsupportedTypeException($type)
                );
            }

            hash_update($context->hashContext, $typeData);

            if (1 === $dataSize) {
                $data = '';
            } else {
                $data = substr($data, 1);
            }

            $dataSize -= 1;
            $consumed += 1;
        }

        if (!$context->isInitialized) {
            if ($dataSize < 16) {
                if ($isEnd) {
                    $this->finalizeContext($context);

                    throw new DecryptionFailedException($this->key());
                }

                return array('', $consumed);
            }

            $iv = substr($data, 0, 16);
            mcrypt_generic_init(
                $context->mcryptModule,
                $this->key()->encryptionSecret(),
                $iv
            );

            hash_update($context->hashContext, $iv);
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
            $requiredSize = 16 + $context->hashSize;
        } else {
            $requiredSize = 32 + $context->hashSize;
        }

        if ($dataSize < $requiredSize) {
            if ($isEnd) {
                $this->finalizeContext($context);

                throw new DecryptionFailedException($this->key());
            }

            return array('', $consumed);
        }

        if ($isEnd) {
            $consume = $dataSize - $context->hashSize;
            $hash = substr($data, $consume);
            $consumedData = substr($data, 0, $consume);
            $consumed += $dataSize;
        } else {
            $consume = $this->blocksSize(
                $dataSize - 16 - $context->hashSize,
                16,
                $isEnd
            );
            $consumed += $consume;
            $consumedData = substr($data, 0, $consume);
        }

        hash_update($context->hashContext, $consumedData);

        if ($isEnd) {
            $context->isHashFinalized = true;
            if (hash_final($context->hashContext, true) !== $hash) {
                $this->finalizeContext($context);

                throw new DecryptionFailedException($this->key());
            }
        }

        $output = mdecrypt_generic($context->mcryptModule, $consumedData);

        if ($isEnd) {
            try {
                $output = $this->unpadder()->unpad($output);
            } catch (InvalidPaddingException $e) {
                $this->finalizeContext($context);

                throw new DecryptionFailedException($this->key(), $e);
            }

            $this->finalizeContext($context);
        }

        return array($output, $consumed);
    }

    private function initializeContext()
    {
        $context = new DecryptTransformContext;

        $context->mcryptModule = mcrypt_module_open(
            MCRYPT_RIJNDAEL_128,
            '',
            MCRYPT_MODE_CBC,
            ''
        );

        $context->hashContext = hash_init(
            'sha' . $this->key()->authenticationSecretBits(),
            HASH_HMAC,
            $this->key()->authenticationSecret()
        );
        $context->hashSize = $this->key()->authenticationSecretBytes();

        return $context;
    }

    private function finalizeContext(DecryptTransformContext &$context)
    {
        if (null !== $context->mcryptModule) {
            if ($context->isInitialized) {
                mcrypt_generic_deinit($context->mcryptModule);
            }

            mcrypt_module_close($context->mcryptModule);
        }

        if (!$context->isHashFinalized) {
            hash_final($context->hashContext);
        }

        $context = null;
    }

    private $key;
    private $unpadder;
}
