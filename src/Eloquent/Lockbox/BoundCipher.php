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
 * The standard Lockbox bi-directional cipher, with a bound key.
 */
class BoundCipher implements
    BoundEncryptionCipherInterface,
    BoundDecryptionCipherInterface
{
    /**
     * Construct a new bound bi-directional encryption cipher.
     *
     * @param Key\PrivateKeyInterface        $privateKey       The key to use.
     * @param EncryptionCipherInterface|null $encryptionCipher The encryption cipher to use.
     * @param DecryptionCipherInterface|null $decryptionCipher The decryption cipher to use.
     */
    public function __construct(
        Key\PrivateKeyInterface $privateKey,
        EncryptionCipherInterface $encryptionCipher = null,
        DecryptionCipherInterface $decryptionCipher = null
    ) {
        if (null === $encryptionCipher) {
            $encryptionCipher = new EncryptionCipher;
        }
        if (null === $decryptionCipher) {
            $decryptionCipher = new DecryptionCipher;
        }

        $this->privateKey = $privateKey;
        $this->publicKey = $privateKey->publicKey();
        $this->encryptionCipher = $encryptionCipher;
        $this->decryptionCipher = $decryptionCipher;
    }

    /**
     * Get the private key.
     *
     * @return Key\PrivateKeyInterface The private key.
     */
    public function privateKey()
    {
        return $this->privateKey;
    }

    /**
     * Get the public key.
     *
     * @return Key\PublicKeyInterface The public key.
     */
    public function publicKey()
    {
        return $this->publicKey;
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
        return $this->encryptionCipher()->encrypt($this->publicKey(), $data);
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
        return $this->decryptionCipher()->decrypt($this->privateKey(), $data);
    }

    private $privateKey;
    private $publicKey;
    private $encryptionCipher;
    private $decryptionCipher;
}
