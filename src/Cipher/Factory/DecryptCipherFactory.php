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
 * Creates decrypt ciphers.
 */
class DecryptCipherFactory implements DecryptCipherFactoryInterface
{
    /**
     * Get the static instance of this factory.
     *
     * @return DecryptCipherFactoryInterface The static factory.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Create a new decrypt cipher.
     *
     * @param KeyInterface $key The key to decrypt with.
     *
     * @return CipherInterface The newly created cipher.
     */
    public function createDecryptCipher(KeyInterface $key)
    {
        return new DecryptCipher($key);
    }

    private static $instance;
}
