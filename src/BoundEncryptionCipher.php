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
 * The standard Lockbox encryption cipher, with a bound key.
 */
class BoundEncryptionCipher implements BoundEncryptionCipherInterface
{
    /**
     * Construct a new bound encryption cipher.
     *
     * @param Key\KeyInterface               $key    The key to use.
     * @param EncryptionCipherInterface|null $cipher The cipher to use.
     */
    public function __construct(
        Key\KeyInterface $key,
        EncryptionCipherInterface $cipher = null
    ) {
        if (null === $cipher) {
            $cipher = new EncryptionCipher;
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
     * @return EncryptionCipherInterface The cipher;
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

    private $key;
    private $cipher;
}
