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
 * The interface implemented by encryption keys.
 */
interface KeyInterface
{
    /**
     * Get the size of the key in bits.
     *
     * @return integer The size of the key in bits.
     */
    public function size();

    /**
     * Get the modulus.
     *
     * @return string The modulus.
     */
    public function modulus();

    /**
     * Get the public exponent.
     *
     * @return string The public exponent.
     */
    public function publicExponent();

    /**
     * Get the public key for this key.
     *
     * @param KeyFactoryInterface|null $factory The key factory to use.
     *
     * @return PublicKeyInterface The public key.
     */
    public function publicKey(KeyFactoryInterface $factory = null);

    /**
     * Get the string representation of this key.
     *
     * @return string The string representation.
     */
    public function __toString();
}
