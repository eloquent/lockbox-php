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
}
