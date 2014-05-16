<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Password\Cipher\Parameters;

use Eloquent\Lockbox\Cipher\Parameters\CipherParametersInterface;
use Eloquent\Lockbox\Password\PasswordInterface;

/**
 * The interface implemented by password encrypt parameters.
 */
interface PasswordEncryptParametersInterface extends CipherParametersInterface
{
    /**
     * Get the password.
     *
     * @return PasswordInterface The password.
     */
    public function password();

    /**
     * Get the number of hash iterations.
     *
     * @return integer The number of hash iterations.
     */
    public function iterations();

    /**
     * Get the salt to use for key derivation.
     *
     * @return string|null The salt to use for key derivation, or null if none was specified.
     */
    public function salt();

    /**
     * Get the initialization vector.
     *
     * @return string|null The initialization vector, or null if none was specified.
     */
    public function iv();
}
