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

/**
 * Cipher parameters for decrypting data with a password.
 */
class PasswordDecryptParameters implements PasswordDecryptParametersInterface
{
    /**
     * Construct a new decrypt parameters instance.
     *
     * @param string $password The password to use.
     */
    public function __construct($password)
    {
        $this->password = $password;
    }

    /**
     * Get the password.
     *
     * @return string The password.
     */
    public function password()
    {
        return $this->password;
    }

    private $password;
}
