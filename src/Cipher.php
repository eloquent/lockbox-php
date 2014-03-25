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

/**
 * The standard Lockbox bi-directional cipher.
 */
class Cipher implements CipherInterface
{
    /**
     * Get the static instance of this cipher.
     *
     * @return CipherInterface The static cipher.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new bi-directional encryption cipher.
     *
     * @param EncryptionCipherInterface|null $encryptionCipher The encryption cipher to use.
     * @param DecryptionCipherInterface|null $decryptionCipher The decryption cipher to use.
     */
    public function __construct(
        EncryptionCipherInterface $encryptionCipher = null,
        DecryptionCipherInterface $decryptionCipher = null
    ) {
        if (null === $encryptionCipher) {
            $encryptionCipher = EncryptionCipher::instance();
        }
        if (null === $decryptionCipher) {
            $decryptionCipher = DecryptionCipher::instance();
        }

        $this->encryptionCipher = $encryptionCipher;
        $this->decryptionCipher = $decryptionCipher;
    }

    /**
     * Get the encryption cipher.
     *
     * @return EncryptionCipherInterface The encryption cipher.
     */
    public function encryptionCipher()
    {
        return $this->encryptionCipher;
    }

    /**
     * Get the decryption cipher.
     *
     * @return DecryptionCipherInterface The decryption cipher.
     */
    public function decryptionCipher()
    {
        return $this->decryptionCipher;
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
        return $this->encryptionCipher()->encrypt($key, $data);
    }

    /**
     * Decrypt a data packet.
     *
     * @param Key\KeyInterface $key  The key to decrypt with.
     * @param string           $data The data to decrypt.
     *
     * @return string                              The decrypted data.
     * @throws Exception\DecryptionFailedException If the decryption failed.
     */
    public function decrypt(Key\KeyInterface $key, $data)
    {
        return $this->decryptionCipher()->decrypt($key, $data);
    }

    private static $instance;
    private $encryptionCipher;
    private $decryptionCipher;
}
