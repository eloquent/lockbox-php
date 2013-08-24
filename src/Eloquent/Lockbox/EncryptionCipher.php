<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Eloquent\Lockbox;

/**
 * The standard Lockbox encryption cipher.
 */
class EncryptionCipher implements EncryptionCipherInterface
{
    /**
     * Construct a new encryption cipher.
     *
     * @param integer|null $randomSource The random source to use.
     */
    public function __construct($randomSource = null)
    {
        if (null === $randomSource) {
            $randomSource = MCRYPT_DEV_URANDOM;
        }

        $this->randomSource = $randomSource;
    }

    /**
     * @return integer
     */
    public function randomSource()
    {
        return $this->randomSource;
    }

    /**
     * Encrypt a data packet.
     *
     * @param Key\PublicKeyInterface $key  The key to encrypt with.
     * @param string                 $data The data to encrypt.
     *
     * @return string The encrypted data.
     */
    public function encrypt(Key\PublicKeyInterface $key, $data)
    {
        $generatedKey = $this->generateKey();
        $iv = $this->generateIv();

        openssl_public_encrypt(
            $generatedKey . $iv,
            $encryptedKeyAndIv,
            $key->handle(),
            OPENSSL_PKCS1_OAEP_PADDING
        );

        return $this->base64UriEncode(
            $encryptedKeyAndIv .
            $this->encryptAes($generatedKey, $iv, sha1($data, true) . $data)
        );
    }

    /**
     * Generate an encryption key.
     *
     * @return string The encryption key.
     */
    protected function generateKey()
    {
        return mcrypt_create_iv(32, $this->randomSource());
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

    /**
     * Encode a string using Base 64 encoding with URI and filename safe
     * alphabet.
     *
     * @link http://tools.ietf.org/html/rfc4648#section-5
     *
     * @param string $data The data to encode.
     *
     * @return string The encoded data.
     */
    protected function base64UriEncode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private $randomSource;
}
