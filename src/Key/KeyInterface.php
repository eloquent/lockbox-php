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
 * The interface implemented by encryption keys.
 */
interface KeyInterface
{
    /**
     * Get the encryption secret.
     *
     * @return string The encryption secret.
     */
    public function encryptionSecret();

    /**
     * Get the authentication secret.
     *
     * @return string The authentication secret.
     */
    public function authenticationSecret();

    /**
     * Get the name.
     *
     * @return string|null The name, or null if the key has no name.
     */
    public function name();

    /**
     * Get the description.
     *
     * @return string|null The description, or null if the key has no description.
     */
    public function description();

    /**
     * Get the size of the encryption secret in bits.
     *
     * @return integer The size of the encryption secret in bits.
     */
    public function encryptionSecretSize();

    /**
     * Get the size of the authentication secret in bits.
     *
     * @return integer The size of the authentication secret in bits.
     */
    public function authenticationSecretSize();
}
