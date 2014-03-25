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
 * The interface implemented by encryption keys.
 */
interface KeyInterface
{
    /**
     * Get the raw key data.
     *
     * @return string The raw key data.
     */
    public function data();

    /**
     * Get the name.
     *
     * @return string|null The name, or null if the key has no name.
     */
    public function name();

    /**
     * Get the description.
     *
     * @return string|null The description, or null if the key has no description.
     */
    public function description();

    /**
     * Get the size of the key in bits.
     *
     * @return integer The size of the key in bits.
     */
    public function size();

    /**
     * Get the string representation of this key.
     *
     * @return string The string representation.
     */
    public function string();

    /**
     * Get the string representation of this key.
     *
     * @return string The string representation.
     */
    public function __toString();
}
