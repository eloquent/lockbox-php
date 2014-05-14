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

use Eloquent\Lockbox\Cipher\Result\CipherResultInterface;
use Eloquent\Lockbox\Stream\CipherStreamInterface;

/**
 * Binds a key to a decrypter.
 */
class BoundDecrypter implements BoundDecrypterInterface
{
    /**
     * Construct a new bound decrypter.
     *
     * @param Key\KeyInterface        $key       The key to use.
     * @param DecrypterInterface|null $decrypter The decrypter to use.
     */
    public function __construct(
        Key\KeyInterface $key,
        DecrypterInterface $decrypter = null
    ) {
        if (null === $decrypter) {
            $decrypter = Decrypter::instance();
        }

        $this->key = $key;
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
     * Get the decrypter.
     *
     * @return DecrypterInterface The decrypter;
     */
    public function decrypter()
    {
        return $this->decrypter;
    }

    /**
     * Decrypt a data packet.
     *
     * @param string $data The data to decrypt.
     *
     * @return CipherResultInterface The decryption result.
     */
    public function decrypt($data)
    {
        return $this->decrypter()->decrypt($this->key(), $data);
    }

    /**
     * Create a new decrypt stream.
     *
     * @return CipherStreamInterface The newly created decrypt stream.
     */
    public function createDecryptStream()
    {
        return $this->decrypter()->createDecryptStream($this->key());
    }

    private $key;
    private $decrypter;
}
