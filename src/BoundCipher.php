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

use Eloquent\Confetti\TransformStreamInterface;
use Eloquent\Lockbox\Result\DecryptionResultInterface;

/**
 * Binds a key to a cipher.
 */
class BoundCipher implements BoundCipherInterface
{
    /**
     * Construct a new bound cipher.
     *
     * @param Key\KeyInterface     $key    The key to use.
     * @param CipherInterface|null $cipher The cipher to use.
     */
    public function __construct(
        Key\KeyInterface $key,
        CipherInterface $cipher = null
    ) {
        if (null === $cipher) {
            $cipher = Cipher::instance();
        }

        $this->key = $key;
        $this->cipher = $cipher;
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
     * Get the cipher.
     *
     * @return CipherInterface The cipher.
     */
    public function cipher()
    {
        return $this->cipher;
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
        return $this->cipher()->encrypt($this->key(), $data);
    }

    /**
     * Decrypt a data packet.
     *
     * @param string $data The data to decrypt.
     *
     * @return DecryptionResultInterface The decryption result.
     */
    public function decrypt($data)
    {
        return $this->cipher()->decrypt($this->key(), $data);
    }

    /**
     * Create a new encrypt stream.
     *
     * @return TransformStreamInterface The newly created encrypt stream.
     */
    public function createEncryptStream()
    {
        return $this->cipher()->createEncryptStream($this->key());
    }

    /**
     * Create a new decrypt stream.
     *
     * @return TransformStreamInterface The newly created decrypt stream.
     */
    public function createDecryptStream()
    {
        return $this->cipher()->createDecryptStream($this->key());
    }

    private $key;
    private $cipher;
}
