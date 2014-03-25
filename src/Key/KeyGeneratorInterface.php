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
 * The interface implemented by encryption key generators.
 */
interface KeyGeneratorInterface
{
    /**
     * Generate a new key.
     *
     * @param integer|null $size        The size of the key in bits.
     * @param string|null  $name        The name.
     * @param string|null  $description The description.
     *
     * @return KeyInterface                      The generated key.
     * @throws Exception\InvalidKeySizeException If the requested key size is invalid.
     */
    public function generateKey(
        $size = null,
        $name = null,
        $description = null
    );
}
