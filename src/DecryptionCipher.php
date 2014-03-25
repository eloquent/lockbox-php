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
 * The standard Lockbox decryption cipher.
 */
class DecryptionCipher implements DecryptionCipherInterface
{
    /**
     * Decrypt a data packet.
     *
     * @param Key\PrivateKeyInterface $key  The key to decrypt with.
     * @param string                  $data The data to decrypt.
     *
     * @return string                              The decrypted data.
     * @throws Exception\DecryptionFailedException If the decryption failed.
     */
    public function decrypt(Key\PrivateKeyInterface $key, $data)
    {
        try {
            $data = $this->base64UriDecode($data);
        } catch (Exception\InvalidEncodingException $e) {
            throw new Exception\DecryptionFailedException($e);
        }

        $keyAndIv = substr($data, 0, $key->size() / 8);
        if (
            !openssl_private_decrypt(
                $keyAndIv,
                $keyAndIv,
                $key->handle(),
                OPENSSL_PKCS1_OAEP_PADDING
            )
        ) {
            throw new Exception\DecryptionFailedException;
        }

        $generatedKey = substr($keyAndIv, 0, 32);
        if (false === $generatedKey) {
            throw new Exception\DecryptionFailedException;
        }

        $iv = substr($keyAndIv, 32);
        if (false === $iv) {
            throw new Exception\DecryptionFailedException;
        }

        $data = $this->decryptAes(
            $generatedKey,
            $iv,
            substr($data, $key->size() / 8)
        );

        $hash = substr($data, -20);
        $data = substr($data, 0, -20);

        if (sha1($data, true) !== $hash) {
            throw new Exception\DecryptionFailedException;
        }

        return $data;
    }

    /**
     * Decrypt some data with AES and PKCS #7 padding.
     *
     * @param string $key  The key to use.
     * @param string $iv   The initialization vector to use.
     * @param string $data The data to decrypt.
     *
     * @return string                              The decrypted data.
     * @throws Exception\DecryptionFailedException If the decryption failed.
     */
    protected function decryptAes($key, $iv, $data)
    {
        $data = mcrypt_decrypt(
            MCRYPT_RIJNDAEL_128,
            $key,
            $data,
            MCRYPT_MODE_CBC,
            $iv
        );

        try {
            $data = $this->unpad($data);
        } catch (Exception\InvalidPaddingException $e) {
            throw new Exception\DecryptionFailedException($e);
        }

        return $data;
    }

    /**
     * Remove PKCS #7 (RFC 2315) padding from a string.
     *
     * @link http://tools.ietf.org/html/rfc2315
     *
     * @param string $data The padded data.
     *
     * @return string                            The data with padding removed.
     * @throws Exception\InvalidPaddingException If the padding is invalid.
     */
    protected function unpad($data)
    {
        $padSize = ord(substr($data, -1));
        $padding = substr($data, -$padSize);
        if (str_repeat(chr($padSize), $padSize) !== $padding) {
            throw new Exception\InvalidPaddingException;
        }

        return substr($data, 0, -$padSize);
    }

    /**
     * Decode a string encoded using Base 64 encoding with URI and filename safe
     * alphabet.
     *
     * @link http://tools.ietf.org/html/rfc4648#section-5
     *
     * @param string $data The encoded data.
     *
     * @return string                             The decoded data.
     * @throws Exception\InvalidEncodingException If the encoding is invalid.
     */
    protected function base64UriDecode($data)
    {
        $data = base64_decode(
            str_pad(
                strtr($data, '-_', '+/'),
                strlen($data) % 4,
                '=',
                STR_PAD_RIGHT
            ),
            true
        );
        if (false === $data) {
            throw new Exception\InvalidEncodingException;
        }

        return $data;
    }
}
