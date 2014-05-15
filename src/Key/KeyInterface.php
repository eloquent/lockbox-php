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

use Eloquent\Lockbox\Cipher\Parameters\CipherParametersInterface;

/**
 * The interface implemented by encryption keys.
 */
interface KeyInterface extends CipherParametersInterface
{
    /**
     * Get the encryption secret.
     *
     * @return string The encryption secret.
     */
    public function encryptionSecret();

    /**
     * Get the size of the encryption secret in bytes.
     *
     * @return integer The size of the encryption secret in bytes.
     */
    public function encryptionSecretBytes();

    /**
     * Get the size of the encryption secret in bits.
     *
     * @return integer The size of the encryption secret in bits.
     */
    public function encryptionSecretBits();

    /**
     * Get the authentication secret.
     *
     * @return string The authentication secret.
     */
    public function authenticationSecret();

    /**
     * Get the size of the authentication secret in bytes.
     *
     * @return integer The size of the authentication secret in bytes.
     */
    public function authenticationSecretBytes();

    /**
     * Get the size of the authentication secret in bits.
     *
     * @return integer The size of the authentication secret in bits.
     */
    public function authenticationSecretBits();

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
}
