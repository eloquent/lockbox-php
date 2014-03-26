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
 * The standard Lockbox cipher, with a bound key.
 */
class BoundCipher implements BoundCipherInterface
{
    /**
     * Construct a new bound cipher.
     *
     * @param Key\KeyInterface        $key       The key to use.
     * @param EncrypterInterface|null $encrypter The encrypter to use.
     * @param DecrypterInterface|null $decrypter The decrypter to use.
     */
    public function __construct(
        Key\KeyInterface $key,
        EncrypterInterface $encrypter = null,
        DecrypterInterface $decrypter = null
    ) {
        if (null === $encrypter) {
            $encrypter = new encrypter;
        }
        if (null === $decrypter) {
            $decrypter = new decrypter;
        }

        $this->key = $key;
        $this->encrypter = $encrypter;
        $this->decrypter = $decrypter;
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
     * Get the encrypter.
     *
     * @return EncrypterInterface The encrypter.
     */
    public function encrypter()
    {
        return $this->encrypter;
    }

    /**
     * Get the decrypter.
     *
     * @return DecrypterInterface The decrypter.
     */
    public function decrypter()
    {
        return $this->decrypter;
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
        return $this->encrypter()->encrypt($this->key(), $data);
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
        return $this->decrypter()->decrypt($this->key(), $data);
    }

    private $key;
    private $encrypter;
    private $decrypter;
}
