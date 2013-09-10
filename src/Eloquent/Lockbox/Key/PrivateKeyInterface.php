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
 * The interface implemented by private encryption keys.
 */
interface PrivateKeyInterface extends KeyInterface
{
    /**
     * Get the private exponent.
     *
     * @return string The private exponent.
     */
    public function privateExponent();

    /**
     * Get the first prime, or 'P'.
     *
     * @return string The first prime.
     */
    public function prime1();

    /**
     * Get the second prime, or 'Q'.
     *
     * @return string The second prime.
     */
    public function prime2();

    /**
     * Get the first prime exponent, or 'DP'.
     *
     * @return string The first prime exponent.
     */
    public function primeExponent1();

    /**
     * Get the second prime exponent, or 'DQ'.
     *
     * @return string The second prime exponent.
     */
    public function primeExponent2();

    /**
     * Get the coefficient, or 'QInv'.
     *
     * @return string The coefficient.
     */
    public function coefficient();

    /**
     * Get the string representation of this key.
     *
     * @param string|null $password The password to encrypt the key with.
     *
     * @return string The string representation.
     */
    public function string($password = null);
}
