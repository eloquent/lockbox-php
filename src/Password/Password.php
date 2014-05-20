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

use Eloquent\Lockbox\Password\Exception\InvalidPasswordException;

/**
 * Respresents a password.
 */
class Password implements PasswordInterface
{
    /**
     * Adapt the supplied password into a password instance.
     *
     * @param PasswordInterface|string $password The password to adapt.
     *
     * @return PasswordInterface        The password instance.
     * @throws InvalidPasswordException If the supplied password cannot be adapted.
     */
    public static function adapt($password)
    {
        if ($password instanceof PasswordInterface) {
            return $password;
        }

        return new Password($password);
    }

    /**
     * Construct a new password.
     *
     * @param string $password The password string.
     */
    public function __construct($password)
    {
        if (!is_string($password)) {
            throw new InvalidPasswordException($password);
        }

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
