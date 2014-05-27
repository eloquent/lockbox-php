<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Key\Factory;

use Eloquent\Lockbox\Key\Exception\InvalidKeyParameterExceptionInterface;
use Eloquent\Lockbox\Key\Key;
use Eloquent\Lockbox\Key\KeyInterface;

/**
 * Creates encryption keys.
 */
class KeyFactory implements KeyFactoryInterface
{
    /**
     * Get the static instance of this factory.
     *
     * @return KeyFactoryInterface The static factory.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Create a new key from existing key data.
     *
     * @param string      $encryptSecret The encrypt secret.
     * @param string      $authSecret    The auth secret.
     * @param string|null $name          The name.
     * @param string|null $description   The description.
     *
     * @return KeyInterface                          The key.
     * @throws InvalidKeyParameterExceptionInterface If the supplied arguments are invalid.
     */
    public function createKey(
        $encryptSecret,
        $authSecret,
        $name = null,
        $description = null
    ) {
        return new Key($encryptSecret, $authSecret, $name, $description);
    }

    private static $instance;
}
