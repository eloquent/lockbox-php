<?php // @codeCoverageIgnoreStart

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
 * The interface implemented by encryption key factories.
 */
interface KeyFactoryInterface
{
    /**
     * Create a new key from existing key data.
     *
     * @param string      $encryptionSecret     The encryption secret.
     * @param string      $authenticationSecret The authentication secret.
     * @param string|null $name                 The name.
     * @param string|null $description          The description.
     *
     * @return KeyInterface                           The key.
     * @throws Exception\InvalidKeyExceptionInterface If the key is invalid.
     */
    public function createKey(
        $encryptionSecret,
        $authenticationSecret,
        $name = null,
        $description = null
    );
}
