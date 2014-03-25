<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Key;

/**
 * The interface implemented by encryption key factories.
 */
interface KeyFactoryInterface
{
    /**
     * Generate a new private key.
     *
     * @param integer|null $size The size of the key in bits.
     *
     * @return PrivateKeyInterface The generated key.
     */
    public function generatePrivateKey($size = null);

    /**
     * Create a new private key.
     *
     * @param string      $key      The PEM formatted private key.
     * @param string|null $password The key password.
     *
     * @return PrivateKeyInterface                  The private key.
     * @throws Exception\InvalidPrivateKeyException If the key is invalid.
     */
    public function createPrivateKey($key, $password = null);

    /**
     * Create a new public key.
     *
     * @param string $key The PEM formatted public key.
     *
     * @return PublicKeyInterface                  The public key.
     * @throws Exception\InvalidPublicKeyException If the key is invalid.
     */
    public function createPublicKey($key);

    /**
     * Create a new private key from a file.
     *
     * @param string      $path     The path to the PEM formatted private key.
     * @param string|null $password The key password.
     *
     * @return PrivateKeyInterface                  The private key.
     * @throws Exception\ReadException              If the file cannot be read.
     * @throws Exception\InvalidPrivateKeyException If the key is invalid.
     */
    public function createPrivateKeyFromFile($path, $password = null);

    /**
     * Create a new public key from a file.
     *
     * @param string $path The path to the PEM formatted public key.
     *
     * @return PublicKeyInterface                  The public key.
     * @throws Exception\ReadException             If the file cannot be read.
     * @throws Exception\InvalidPublicKeyException If the key is invalid.
     */
    public function createPublicKeyFromFile($path);
}
