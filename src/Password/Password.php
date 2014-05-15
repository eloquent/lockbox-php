<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Password;

/**
 * Respresents a password.
 */
class Password implements PasswordInterface
{
    /**
     * Construct a new password.
     *
     * @param string $password The password string.
     */
    public function __construct($password)
    {
        $this->password = $password;
    }

    /**
     * Get the string representation of this password.
     *
     * @return string The password string.
     */
    public function string()
    {
        return $this->password;
    }

    /**
     * Get the string representation of this password.
     *
     * @return string The password string.
     */
    public function __toString()
    {
        return $this->string();
    }

    private $password;
}
