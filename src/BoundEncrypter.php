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

use Eloquent\Lockbox\Stream\CipherStreamInterface;

/**
 * Binds a key to an encrypter.
 */
class BoundEncrypter implements BoundEncrypterInterface
{
    /**
     * Construct a new bound encrypter.
     *
     * @param Key\KeyInterface        $key       The key to use.
     * @param EncrypterInterface|null $encrypter The encrypter to use.
     */
    public function __construct(
        Key\KeyInterface $key,
        EncrypterInterface $encrypter = null
    ) {
        if (null === $encrypter) {
            $encrypter = Encrypter::instance();
        }

        $this->key = $key;
        $this->encrypter = $encrypter;
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
     * @return EncrypterInterface The encrypter;
     */
    public function encrypter()
    {
        return $this->encrypter;
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
     * Create a new encrypt stream.
     *
     * @return CipherStreamInterface The newly created encrypt stream.
     */
    public function createEncryptStream()
    {
        return $this->encrypter()->createEncryptStream($this->key());
    }

    private $key;
    private $encrypter;
}
