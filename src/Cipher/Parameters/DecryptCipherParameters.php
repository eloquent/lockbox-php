<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Cipher\Parameters;

use Eloquent\Lockbox\Key\KeyInterface;

/**
 * Cipher parameters for decrypting data with a key.
 */
class DecryptCipherParameters implements DecryptCipherParametersInterface
{
    /**
     * Construct a new decrypt cipher parameters instance.
     *
     * @param KeyInterface $key The key to use.
     */
    public function __construct(KeyInterface $key)
    {
        $this->key = $key;
    }

    /**
     * Get the key.
     *
     * @return KeyInterface The key.
     */
    public function key()
    {
        return $this->key;
    }

    private $key;
}
