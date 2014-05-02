<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Cipher\Factory;

use Eloquent\Lockbox\Cipher\CipherInterface;
use Eloquent\Lockbox\Key\KeyInterface;

/**
 * The interface implemented by encrypt cipher factories.
 */
interface EncryptCipherFactoryInterface
{
    /**
     * Create a new encrypt cipher.
     *
     * @param KeyInterface $key The key to encrypt with.
     * @param string|null  $iv  The initialization vector to use, or null to generate one.
     *
     * @return CipherInterface The newly created cipher.
     */
    public function createEncryptCipher(KeyInterface $key, $iv = null);
}
