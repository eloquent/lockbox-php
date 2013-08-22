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
        $data = base64_decode($data, true);
        if (false === $data) {
            throw new Exception\DecryptionFailedException;
        }

        $keyAndIv = substr($data, 0, $key->bits() / 8);
        if (!openssl_private_decrypt($keyAndIv, $keyAndIv, $key->handle())) {
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
            substr($data, $key->bits() / 8)
        );

        $hash = substr($data, 0, 20);
        $data = substr($data, 20);
        if (false === $data) {
            $data = '';
        }

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
     * @return string The decrypted data.
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
}
