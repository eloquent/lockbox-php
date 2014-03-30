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
use Eloquent\Lockbox\Key\KeyDeriver;
use Eloquent\Lockbox\Key\KeyDeriverInterface;
use Eloquent\Lockbox\Random\DevUrandom;
use Eloquent\Lockbox\Random\RandomSourceInterface;
use Exception;

/**
 * A data transform for encryption of streaming data with a password.
 */
class PasswordEncryptTransform extends AbstractTransform
{
    /**
     * Construct a new password encrypt data transform.
     *
     * @param string                     $password     The password to encrypt with.
     * @param integer                    $iterations   The number of hash iterations to use.
     * @param KeyDeriverInterface|null   $keyDeriver   The key deriver to use.
     * @param RandomSourceInterface|null $randomSource The random source to use.
     */
    public function __construct(
        $password,
        $iterations,
        KeyDeriverInterface $keyDeriver = null,
        RandomSourceInterface $randomSource = null
    ) {
        if (null === $keyDeriver) {
            $keyDeriver = KeyDeriver::instance();
        }
        if (null === $randomSource) {
            $randomSource = DevUrandom::instance();
        }

        $this->password = $password;
        $this->iterations = $iterations;
        $this->keyDeriver = $keyDeriver;
        $this->randomSource = $randomSource;
        $this->version = chr(1);
        $this->type = chr(2);
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
     * Get the number of hash iterations.
     *
     * @return integer The hash iterations.
     */
    public function iterations()
    {
        return $this->iterations;
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
     * @return tuple<string,integer> A 2-tuple of the transformed data, and the number of bytes consumed.
     * @throws Exception             If the data cannot be transformed.
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

        list($key, $salt) = $this->keyDeriver()->deriveKeyFromPassword(
            $this->password(),
            $this->iterations()
        );

        $context->mcryptModule = mcrypt_module_open(
            MCRYPT_RIJNDAEL_128,
            '',
            MCRYPT_MODE_CBC,
            ''
        );

        $iv = $this->randomSource()->generate(16);
        mcrypt_generic_init(
            $context->mcryptModule,
            $key->encryptionSecret(),
            $iv
        );

        $context->hashContext = hash_init(
            'sha256',
            HASH_HMAC,
            $key->authenticationSecret()
        );

        $context->outputBuffer = $this->version . $this->type .
            pack('N', $this->iterations()) . $salt . $iv;

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

    private $password;
    private $iterations;
    private $keyDeriver;
    private $randomSource;
    private $version;
    private $type;
}
