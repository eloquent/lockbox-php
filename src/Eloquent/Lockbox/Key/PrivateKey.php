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
 * Represents a private encryption key.
 */
class PrivateKey extends AbstractKey implements PrivateKeyInterface
{
    /**
     * Construct a new private key.
     *
     * @param resource $handle The key handle.
     *
     * @throws Exception\InvalidPrivateKeyException If the supplied handle does not represent an RSA private key.
     */
    public function __construct($handle)
    {
        parent::__construct($handle);

        if (
            OPENSSL_KEYTYPE_RSA !== $this->detail('type') ||
            !$this->hasRsaDetail('d')
        ) {
            throw new Exception\InvalidPrivateKeyException($this->detail('key'));
        }
    }

    /**
     * Get the private exponent.
     *
     * @return string The private exponent.
     */
    public function privateExponent()
    {
        return $this->rsaDetail('d');
    }

    /**
     * Get the first prime, or 'P'.
     *
     * @return string The first prime.
     */
    public function prime1()
    {
        return $this->rsaDetail('p');
    }

    /**
     * Get the second prime, or 'Q'.
     *
     * @return string The second prime.
     */
    public function prime2()
    {
        return $this->rsaDetail('q');
    }

    /**
     * Get the first prime exponent, or 'DP'.
     *
     * @return string The first prime exponent.
     */
    public function primeExponent1()
    {
        return $this->rsaDetail('dmp1');
    }

    /**
     * Get the second prime exponent, or 'DQ'.
     *
     * @return string The second prime exponent.
     */
    public function primeExponent2()
    // @codeCoverageIgnoreStart
    {
        // @codeCoverageIgnoreEnd
        return $this->rsaDetail('dmq1');
    }

    /**
     * Get the coefficient, or 'QInv'.
     *
     * @return string The coefficient.
     */
    public function coefficient()
    {
        return $this->rsaDetail('iqmp');
    }

    /**
     * Get the public key for this key.
     *
     * @param KeyFactoryInterface|null $factory The key factory to use.
     *
     * @return PublicKeyInterface The public key.
     */
    public function publicKey(KeyFactoryInterface $factory = null)
    {
        if (null === $factory) {
            $factory = new KeyFactory;
        }

        return $factory->createPublicKey($this->detail('key'));
    }

    /**
     * Get the string representation of this key.
     *
     * @param string|null $password The password to encrypt the key with.
     *
     * @return string The string representation.
     */
    public function string($password = null)
    {
        openssl_pkey_export($this->handle(), $pem, $password);

        return $pem;
    }

    /**
     * Get the string representation of this key.
     *
     * @return string The string representation.
     */
    public function __toString()
    {
        return $this->string();
    }
}
