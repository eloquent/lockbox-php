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

use Eloquent\Lockbox\Cipher\EncryptionCipher;
use Eloquent\Lockbox\Key\KeyInterface;

/**
 * Creates encryption ciphers.
 */
class EncryptionCipherFactory implements EncryptionCipherFactoryInterface
{
    /**
     * Get the static instance of this factory.
     *
     * @return EncryptionCipherFactoryInterface The static factory.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Create a new encryption cipher.
     *
     * @param KeyInterface $key The key to encrypt with.
     * @param string       $iv  The initialization vector to use.
     */
    public function createEncryptionCipher(KeyInterface $key, $iv)
    {
        return new EncryptionCipher($key, $iv);
    }

    private static $instance;
}
