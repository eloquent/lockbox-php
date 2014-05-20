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
     * Get the encrypt secret.
     *
     * @return string The encrypt secret.
     */
    public function encryptSecret();

    /**
     * Get the size of the encrypt secret in bytes.
     *
     * @return integer The size of the encrypt secret in bytes.
     */
    public function encryptSecretBytes();

    /**
     * Get the size of the encrypt secret in bits.
     *
     * @return integer The size of the encrypt secret in bits.
     */
    public function encryptSecretBits();

    /**
     * Get the auth secret.
     *
     * @return string The auth secret.
     */
    public function authSecret();

    /**
     * Get the size of the auth secret in bytes.
     *
     * @return integer The size of the auth secret in bytes.
     */
    public function authSecretBytes();

    /**
     * Get the size of the auth secret in bits.
     *
     * @return integer The size of the auth secret in bits.
     */
    public function authSecretBits();

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
