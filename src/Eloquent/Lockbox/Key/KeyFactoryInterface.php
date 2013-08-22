<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Key;

/**
 * The interface implemented by encryption key factories.
 */
interface KeyFactoryInterface
{
    /**
     * Create a new private key.
     *
     * @param string $key           The PEM formatted private key.
     * @param string|null $password The key password.
     *
     * @return PrivateKeyInterface
     * @throws Exception\InvalidPrivateKeyException If the key is invalid.
     */
    public function createPrivateKey($key, $password = null);

    /**
     * Create a new public key.
     *
     * @param string $key The PEM formatted public key.
     *
     * @return PublicKeyInterface
     * @throws Exception\InvalidPublicKeyException If the key is invalid.
     */
    public function createPublicKey($key);

    /**
     * Create a new private key from a file.
     *
     * @param string      $path The path to the PEM formatted private key.
     * @param string|null $password The key password.
     *
     * @return PrivateKeyInterface
     * @throws Exception\ReadException              If the file cannot be read.
     * @throws Exception\InvalidPrivateKeyException If the key is invalid.
     */
    public function createPrivateKeyFromFile($path, $password = null);

    /**
     * Create a new public key from a file.
     *
     * @param string $path The path to the PEM formatted public key.
     *
     * @return PublicKeyInterface
     * @throws Exception\ReadException             If the file cannot be read.
     * @throws Exception\InvalidPublicKeyException If the key is invalid.
     */
    public function createPublicKeyFromFile($path);
}
