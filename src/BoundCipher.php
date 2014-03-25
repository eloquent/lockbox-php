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
 * The standard Lockbox bi-directional cipher, with a bound key.
 */
class BoundCipher implements BoundCipherInterface
{
    /**
     * Construct a new bound bi-directional encryption cipher.
     *
     * @param Key\KeyInterface               $key              The key to use.
     * @param EncryptionCipherInterface|null $encryptionCipher The encryption cipher to use.
     * @param DecryptionCipherInterface|null $decryptionCipher The decryption cipher to use.
     */
    public function __construct(
        Key\KeyInterface $key,
        EncryptionCipherInterface $encryptionCipher = null,
        DecryptionCipherInterface $decryptionCipher = null
    ) {
        if (null === $encryptionCipher) {
            $encryptionCipher = new EncryptionCipher;
        }
        if (null === $decryptionCipher) {
            $decryptionCipher = new DecryptionCipher;
        }

        $this->key = $key;
        $this->encryptionCipher = $encryptionCipher;
        $this->decryptionCipher = $decryptionCipher;
    }

    /**
     * Get the key.
     *
     * @return Key\KeyInterface The key.
     */
    public function key()
    {
        return $this->key;
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
     * @param string $data The data to encrypt.
     *
     * @return string The encrypted data.
     */
    public function encrypt($data)
    {
        return $this->encryptionCipher()->encrypt($this->key(), $data);
    }

    /**
     * Decrypt a data packet.
     *
     * @param string $data The data to decrypt.
     *
     * @return string                              The decrypted data.
     * @throws Exception\DecryptionFailedException If the decryption failed.
     */
    public function decrypt($data)
    {
        return $this->decryptionCipher()->decrypt($this->key(), $data);
    }

    private $key;
    private $encryptionCipher;
    private $decryptionCipher;
}
