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
 * The standard Lockbox decryption cipher, with a bound key.
 */
class BoundDecryptionCipher implements BoundDecryptionCipherInterface
{
    /**
     * Construct a new bound decryption cipher.
     *
     * @param Key\PrivateKeyInterface        $key    The key to use.
     * @param DecryptionCipherInterface|null $cipher The cipher to use.
     */
    public function __construct(
        Key\PrivateKeyInterface $key,
        DecryptionCipherInterface $cipher = null
    ) {
        if (null === $cipher) {
            $cipher = new DecryptionCipher;
        }

        $this->key = $key;
        $this->cipher = $cipher;
    }

    /**
     * Get the key.
     *
     * @return Key\PrivateKeyInterface The key.
     */
    public function key()
    {
        return $this->key;
    }

    /**
     * Get the cipher.
     *
     * @return DecryptionCipherInterface The cipher;
     */
    public function cipher()
    {
        return $this->cipher;
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
        return $this->cipher()->decrypt($this->key(), $data);
    }

    private $key;
    private $cipher;
}
