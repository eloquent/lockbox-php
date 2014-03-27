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

use Eloquent\Endec\Base64\Base64UrlEncodeTransform;
use Eloquent\Endec\Transform\AbstractDataTransform;
use Eloquent\Endec\Transform\DataTransformInterface;
use Eloquent\Lockbox\Key\KeyInterface;
use Eloquent\Lockbox\Random\DevUrandom;
use Eloquent\Lockbox\Random\RandomSourceInterface;

/**
 * A data transform for encryption of streaming data.
 */
class EncryptTransform extends AbstractDataTransform
{
    /**
     * Construct a new encrypt data transform.
     *
     * @param KeyInterface                $key               The key to encrypt with.
     * @param RandomSourceInterface|null  $randomSource      The random source to use.
     * @param DataTransformInterface|null $encodingTransform The encoding transform to use.
     */
    public function __construct(
        KeyInterface $key,
        RandomSourceInterface $randomSource = null,
        DataTransformInterface $encodingTransform = null
    ) {
        if (null === $randomSource) {
            $randomSource = DevUrandom::instance();
        }
        if (null === $encodingTransform) {
            $encodingTransform = Base64UrlEncodeTransform::instance();
        }

        $this->key = $key;
        $this->randomSource = $randomSource;
        $this->encodingTransform = $encodingTransform;
        $this->version = pack('n', 1);
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
     * Get the random source.
     *
     * @return RandomSourceInterface The random source.
     */
    public function randomSource()
    {
        return $this->randomSource;
    }

    /**
     * Get the encoding transform.
     *
     * @return DataTransformInterface The encoding transform.
     */
    public function encodingTransform()
    {
        return $this->encodingTransform;
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
     * @return tuple<string,integer>                 A 2-tuple of the transformed data, and the number of bytes consumed.
     * @throws Exception\TransformExceptionInterface If the data cannot be transformed.
     */
    public function transform($data, &$context, $isEnd = false)
    {
        if (null === $context) {
            /*
             * Context contains:
             *
             * 0: mcrypt module
             * 1: hmac hashing context
             * 2: encryption input buffer
             * 3: hashing/encoding input buffer
             * 4: encoding transform context
             */
            $iv = $this->randomSource()->generate(16);
            $context = array(
                mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, ''),
                hash_init(
                    'sha' . $this->key()->authenticationSecretSize(),
                    HASH_HMAC,
                    $this->key()->authenticationSecret()
                ),
                '',
                $this->version . $iv,
                null,
            );
            mcrypt_generic_init($context[0], $this->key()->encryptionSecret(), $iv);
        }

        $dataSize = strlen($data);
        $context[2] .= $data;

        $consume = $this->calculateConsumeBytes($context[2], $isEnd, 16);
        if ($consume) {
            if (strlen($context[2]) === $consume) {
                if ($isEnd) {
                    $padSize = intval(16 - (strlen($context[2]) % 16));
                    $context[3] .= mcrypt_generic(
                        $context[0],
                        $context[2] . str_repeat(chr($padSize), $padSize)
                    );
                } else {
                    $context[3] .= mcrypt_generic($context[0], $context[2]);
                }
                $context[2] = '';
            } else {
                $context[3] .= mcrypt_generic(
                    $context[0],
                    substr($context[2], 0, $consume)
                );
                $context[2] = substr($context[2], $consume);
            }
        }

        list($output, $consumed) = $this->encodingTransform()
            ->transform($context[3], $context[4], false);
        if (strlen($context[3]) === $consumed) {
            hash_update($context[1], $context[3]);
            $context[3] = '';
        } else {
            hash_update($context[1], substr($context[3], 0, $consumed));
            $context[3] = substr($context[3], $consumed);
        }

        if ($isEnd) {
            mcrypt_generic_deinit($context[0]);
            mcrypt_module_close($context[0]);
            hash_update($context[1], $context[3]);
            $context[3] .= hash_final($context[1], true);

            list($endOutput) = $this->encodingTransform()
                ->transform($context[3], $context[4], true);
            $output .= $endOutput;

            $context = null;
        }

        return array($output, $dataSize);
    }

    private $key;
    private $randomSource;
    private $encodingTransform;
    private $version;
}
