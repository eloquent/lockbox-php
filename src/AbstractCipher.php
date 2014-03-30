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

use Eloquent\Endec\Transform\TransformStreamInterface;

/**
 * An abstract base class for implementing ciphers.
 */
abstract class AbstractCipher implements CipherInterface
{
    /**
     * Construct a new cipher.
     *
     * @param EncrypterInterface $encrypter The encrypter to use.
     * @param DecrypterInterface $decrypter The decrypter to use.
     */
    public function __construct(
        EncrypterInterface $encrypter,
        DecrypterInterface $decrypter
    ) {
        $this->encrypter = $encrypter;
        $this->decrypter = $decrypter;
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
     * @param Key\KeyInterface $key  The key to encrypt with.
     * @param string           $data The data to encrypt.
     *
     * @return string The encrypted data.
     */
    public function encrypt(Key\KeyInterface $key, $data)
    {
        return $this->encrypter()->encrypt($key, $data);
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
        return $this->decrypter()->decrypt($key, $data);
    }

    /**
     * Create a new encrypt stream.
     *
     * @param Key\KeyInterface $key The key to encrypt with.
     *
     * @return TransformStreamInterface The newly created encrypt stream.
     */
    public function createEncryptStream(Key\KeyInterface $key)
    {
        return $this->encrypter()->createEncryptStream($key);
    }

    /**
     * Create a new decrypt stream.
     *
     * @param Key\KeyInterface $key The key to decrypt with.
     *
     * @return TransformStreamInterface The newly created decrypt stream.
     */
    public function createDecryptStream(Key\KeyInterface $key)
    {
        return $this->decrypter()->createDecryptStream($key);
    }

    private $encrypter;
    private $decrypter;
}
