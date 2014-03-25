<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox;

use Eloquent\Endec\Base64\Base64Url;
use Eloquent\Endec\EncoderInterface;

/**
 * The standard Lockbox encryption cipher.
 */
class EncryptionCipher implements EncryptionCipherInterface
{
    /**
     * Get the static instance of this cipher.
     *
     * @return EncryptionCipherInterface The static cipher.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new encryption cipher.
     *
     * @param integer|null          $randomSource     The random source to use.
     * @param EncoderInterface|null $base64UrlEncoder The base64url encoder to use.
     */
    public function __construct(
        $randomSource = null,
        EncoderInterface $base64UrlEncoder = null
    ) {
        if (null === $randomSource) {
            $randomSource = MCRYPT_DEV_URANDOM;
        }
        if (null === $base64UrlEncoder) {
            $base64UrlEncoder = Base64Url::instance();
        }

        $this->randomSource = $randomSource;
        $this->base64UrlEncoder = $base64UrlEncoder;
    }

    /**
     * Get the random source.
     *
     * @return integer The random source.
     */
    public function randomSource()
    {
        return $this->randomSource;
    }

    /**
     * Get the base64url encoder.
     *
     * @return EncoderInterface The base64url encoder.
     */
    public function base64UrlEncoder()
    {
        return $this->base64UrlEncoder;
    }

    /**
     * Encrypt a data packet.
     *
     * @param Key\KeyInterface $key  The key to encrypt with.
     * @param string           $data The data to encrypt.
     *
     * @return string The encrypted data.
     */
    public function encrypt(Key\KeyInterface $key, $data)
    {
        $iv = $this->generateIv();

        return $this->base64UrlEncoder()->encode(
            $iv .
            $this->encryptAes($key->data(), $iv, $data . sha1($data, true))
        );
    }

    /**
     * Generate an initialization vector.
     *
     * @return string The initialization vector.
     */
    protected function generateIv()
    {
        return mcrypt_create_iv(16, $this->randomSource());
    }

    /**
     * Encrypt some data with AES and PKCS #7 padding.
     *
     * @param string $key  The key to use.
     * @param string $iv   The initialization vector to use.
     * @param string $data The data to encrypt.
     *
     * @return string The encrypted data.
     */
    protected function encryptAes($key, $iv, $data)
    {
        return mcrypt_encrypt(
            MCRYPT_RIJNDAEL_128,
            $key,
            $this->pad($data),
            MCRYPT_MODE_CBC,
            $iv
        );
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

    private static $instance;
    private $randomSource;
    private $base64UrlEncoder;
}