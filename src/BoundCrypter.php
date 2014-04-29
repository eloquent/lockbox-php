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
 * Binds a key to a crypter.
 */
class BoundCrypter implements BoundCrypterInterface
{
    /**
     * Construct a new bound crypter.
     *
     * @param Key\KeyInterface      $key     The key to use.
     * @param CrypterInterface|null $crypter The crypter to use.
     */
    public function __construct(
        Key\KeyInterface $key,
        CrypterInterface $crypter = null
    ) {
        if (null === $crypter) {
            $crypter = Crypter::instance();
        }

        $this->key = $key;
        $this->crypter = $crypter;
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
     * Get the crypter.
     *
     * @return CrypterInterface The crypter.
     */
    public function crypter()
    {
        return $this->crypter;
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
        return $this->crypter()->encrypt($this->key(), $data);
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
        return $this->crypter()->decrypt($this->key(), $data);
    }

    /**
     * Create a new encrypt stream.
     *
     * @return TransformStreamInterface The newly created encrypt stream.
     */
    public function createEncryptStream()
    {
        return $this->crypter()->createEncryptStream($this->key());
    }

    /**
     * Create a new decrypt stream.
     *
     * @return TransformStreamInterface The newly created decrypt stream.
     */
    public function createDecryptStream()
    {
        return $this->crypter()->createDecryptStream($this->key());
    }

    private $key;
    private $crypter;
}
