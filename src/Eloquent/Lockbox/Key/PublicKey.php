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
 * Represents a public encryption key.
 */
class PublicKey extends AbstractKey implements PublicKeyInterface
{
    /**
     * Construct a new public key.
     *
     * @param resource $handle The key handle.
     *
     * @throws Exception\InvalidPublicKeyException If the supplied handle does not represent an RSA public key.
     */
    public function __construct($handle)
    {
        parent::__construct($handle);

        if (
            OPENSSL_KEYTYPE_RSA !== $this->detail('type') ||
            $this->hasRsaDetail('d')
        ) {
            throw new Exception\InvalidPublicKeyException($this->detail('key'));
        }
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
        return $this;
    }

    /**
     * Get the string representation of this key.
     *
     * @return string The string representation.
     */
    public function string()
    {
        return $this->detail('key');
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
