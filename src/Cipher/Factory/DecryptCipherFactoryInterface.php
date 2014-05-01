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
 * The interface implemented by decrypt cipher factories.
 */
interface DecryptCipherFactoryInterface
{
    /**
     * Create a new decrypt cipher.
     *
     * @param KeyInterface $key The key to decrypt with.
     */
    public function createDecryptCipher(KeyInterface $key);
}
