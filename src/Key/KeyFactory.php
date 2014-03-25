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

use ErrorException;
use Icecave\Isolator\Isolator;

/**
 * Creates encryption keys.
 */
class KeyFactory implements KeyFactoryInterface
{
    /**
     * Construct a new key factory.
     *
     * @param Isolator|null $isolator The isolator to use.
     */
    public function __construct(Isolator $isolator = null)
    {
        $this->isolator = Isolator::get($isolator);
    }

    /**
     * Generate a new private key.
     *
     * @param integer|null $size The size of the key in bits.
     *
     * @return PrivateKeyInterface The generated key.
     */
    public function generatePrivateKey($size = null)
    {
        if (null === $size) {
            $size = 2048;
        }

        return new PrivateKey(
            openssl_pkey_new(array('private_key_bits' => $size))
        );
    }

    /**
     * Create a new private key.
     *
     * @param string      $key      The PEM formatted private key.
     * @param string|null $password The key password.
     *
     * @return PrivateKeyInterface                  The private key.
     * @throws Exception\InvalidPrivateKeyException If the key is invalid.
     */
    public function createPrivateKey($key, $password = null)
    {
        $handle = openssl_pkey_get_private($key, $password);
        if (false === $handle) {
            throw new Exception\InvalidPrivateKeyException($key);
        }

        return new PrivateKey($handle);
    }

    /**
     * Create a new public key.
     *
     * @param string $key The PEM formatted public key.
     *
     * @return PublicKeyInterface                  The public key.
     * @throws Exception\InvalidPublicKeyException If the key is invalid.
     */
    public function createPublicKey($key)
    {
        $handle = openssl_pkey_get_public($key);
        if (false === $handle) {
            throw new Exception\InvalidPublicKeyException($key);
        }

        return new PublicKey($handle);
    }

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
    public function createPrivateKeyFromFile($path, $password = null)
    {
        try {
            $key = $this->isolator->file_get_contents($path);
        } catch (ErrorException $e) {
            throw new Exception\ReadException($path);
        }

        return $this->createPrivateKey($key, $password);
    }

    /**
     * Create a new public key from a file.
     *
     * @param string $path The path to the PEM formatted public key.
     *
     * @return PublicKeyInterface                  The public key.
     * @throws Exception\ReadException             If the file cannot be read.
     * @throws Exception\InvalidPublicKeyException If the key is invalid.
     */
    public function createPublicKeyFromFile($path)
    {
        try {
            $key = $this->isolator->file_get_contents($path);
        } catch (ErrorException $e) {
            throw new Exception\ReadException($path);
        }

        return $this->createPublicKey($key);
    }

    private $isolator;
}
