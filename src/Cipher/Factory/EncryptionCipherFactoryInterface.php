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

use Eloquent\Lockbox\Key\KeyInterface;

/**
 * The interface implemented by encryption cipher factories.
 */
interface EncryptionCipherFactoryInterface
{
    /**
     * Create a new encryption cipher.
     *
     * @param KeyInterface $key The key to encrypt with.
     * @param string|null  $iv  The initialization vector to use, or null to generate one.
     */
    public function createEncryptionCipher(KeyInterface $key, $iv = null);
}
