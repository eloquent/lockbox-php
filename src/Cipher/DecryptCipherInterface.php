<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Cipher;

use Eloquent\Lockbox\Key\KeyInterface;

/**
 * The interface implemented by decrypt ciphers that use keys.
 */
interface DecryptCipherInterface extends CipherInterface
{
    /**
     * Initialize this cipher.
     *
     * @param KeyInterface $key The key to use.
     */
    public function initialize(KeyInterface $key);
}
