<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Password\Exception;

use Exception;

/**
 * The supplied password is invalid.
 */
final class InvalidPasswordException extends Exception
{
    /**
     * Construct a new invalid password exception.
     *
     * @param mixed          $password The invalid password.
     * @param Exception|null $cause    The cause, if available.
     */
    public function __construct($password, Exception $cause = null)
    {
        $this->password = $password;

        parent::__construct(
            sprintf('Invalid password %s.', var_export($password, true)),
            0,
            $cause
        );
    }

    /**
     * Get the invalid password.
     *
     * @return mixed The password.
     */
    public function password()
    {
        return $this->password;
    }

    private $password;
}
