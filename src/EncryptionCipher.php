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
use Eloquent\Lockbox\Random\DevUrandom;
use Eloquent\Lockbox\Random\RandomSourceInterface;

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
     * @param RandomSourceInterface|null $randomSource     The random source to use.
     * @param EncoderInterface|null      $base64UrlEncoder The base64url encoder to use.
     */
    public function __construct(
        RandomSourceInterface $randomSource = null,
        EncoderInterface $base64UrlEncoder = null
    ) {
        if (null === $randomSource) {
            $randomSource = DevUrandom::instance();
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
     * @return RandomSourceInterface The random source.
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
        $iv = $this->randomSource()->generate(16);
        $ciphertext = $this->encryptAes($key, $iv, $data);

        return $this->base64UrlEncoder()->encode(
            $iv .
            $ciphertext .
            $this->authenticationCode($key, $iv . $ciphertext)
        );
    }

    /**
     * Encrypt some data with AES and PKCS #7 padding.
     *
     * @param Key\KeyInterface $key  The key to encrypt with.
     * @param string           $iv   The initialization vector to use.
     * @param string           $data The data to encrypt.
     *
     * @return string The encrypted data.
     */
    protected function encryptAes(Key\KeyInterface $key, $iv, $data)
    {
        return mcrypt_encrypt(
            MCRYPT_RIJNDAEL_128,
            $key->encryptionSecret(),
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

    /**
     * Create a message authentication code for the supplied ciphertext using
     * HMAC-SHA-256.
     *
     * @link https://tools.ietf.org/html/rfc6234
     *
     * @param KeyInterface $key        The key to authenticate with.
     * @param string       $ciphertext The ciphertext.
     *
     * @return string The message authentication code.
     */
    protected function authenticationCode(Key\KeyInterface $key, $ciphertext)
    {
        return hash_hmac(
            'sha256',
            $ciphertext,
            $key->authenticationSecret(),
            true
        );
    }

    private static $instance;
    private $randomSource;
    private $base64UrlEncoder;
}
