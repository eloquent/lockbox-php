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

use Eloquent\Endec\Transform\AbstractDataTransform;
use Eloquent\Endec\Transform\Exception\TransformExceptionInterface;
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
     * @param KeyInterface               $key          The key to encrypt with.
     * @param RandomSourceInterface|null $randomSource The random source to use.
     */
    public function __construct(
        KeyInterface $key,
        RandomSourceInterface $randomSource = null
    ) {
        if (null === $randomSource) {
            $randomSource = DevUrandom::instance();
        }

        $this->key = $key;
        $this->randomSource = $randomSource;
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
     * @return tuple<string,integer>       A 2-tuple of the transformed data, and the number of bytes consumed.
     * @throws TransformExceptionInterface If the data cannot be transformed.
     */
    public function transform($data, &$context, $isEnd = false)
    {
        if (null === $context) {
            $context = $this->initializeContext();
        }

        $dataSize = strlen($data);
        if (!$isEnd && $dataSize < 16) {
            return array('', 0);
        }

        $context->encryptBuffer .= $data;
        $context->encryptBufferSize += $dataSize;
        $consume = $this->blocksSize($context->encryptBufferSize, 16, $isEnd);

        if ($context->encryptBufferSize === $consume) {
            if ($isEnd) {
                $context->outputBuffer .= mcrypt_generic(
                    $context->mcryptModule,
                    $this->pad($context->encryptBuffer)
                );
            } else {
                $context->outputBuffer .= mcrypt_generic(
                    $context->mcryptModule,
                    $context->encryptBuffer
                );
            }
            $context->encryptBuffer = '';
            $context->encryptBufferSize = 0;
        } else {
            $context->outputBuffer .= mcrypt_generic(
                $context->mcryptModule,
                substr($context->encryptBuffer, 0, $consume)
            );
            $context->encryptBuffer = substr($context->encryptBuffer, $consume);
            $context->encryptBufferSize -= $consume;
        }

        hash_update($context->hashContext, $context->outputBuffer);
        $output = $context->outputBuffer;

        if ($isEnd) {
            $output .= $this->finalizeContext($context);
        } else {
            $context->outputBuffer = '';
        }

        return array($output, $dataSize);
    }

    /**
     * Pad a string using PKCS #7 (RFC 2315) padding.
     *
     * @link http://tools.ietf.org/html/rfc2315
     *
     * @param string $data The data to pad.
     *
     * @return string The padded data.
     */
    protected function pad($data)
    {
        $padSize = intval(16 - (strlen($data) % 16));

        return $data . str_repeat(chr($padSize), $padSize);
    }

    private function initializeContext()
    {
        $context = new EncryptTransformContext;

        $context->mcryptModule = mcrypt_module_open(
            MCRYPT_RIJNDAEL_128,
            '',
            MCRYPT_MODE_CBC,
            ''
        );

        $iv = $this->randomSource()->generate(16);
        mcrypt_generic_init(
            $context->mcryptModule,
            $this->key()->encryptionSecret(),
            $iv
        );

        $context->hashContext = hash_init(
            'sha' . $this->key()->authenticationSecretBits(),
            HASH_HMAC,
            $this->key()->authenticationSecret()
        );

        $context->outputBuffer = $this->version . $iv;

        return $context;
    }

    private function finalizeContext(EncryptTransformContext &$context)
    {
        mcrypt_generic_deinit($context->mcryptModule);
        mcrypt_module_close($context->mcryptModule);
        $hash = hash_final($context->hashContext, true);
        $context = null;

        return $hash;
    }

    private $key;
    private $randomSource;
    private $version;
}
