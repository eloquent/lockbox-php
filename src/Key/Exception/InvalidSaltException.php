<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Key\Exception;

use Exception;

/**
 * The supplied salt is invalid.
 */
final class InvalidSaltException extends Exception implements
    InvalidKeyParameterExceptionInterface
{
    /**
     * Construct a new invalid salt exception.
     *
     * @param mixed          $salt  The invalid salt.
     * @param Exception|null $cause The cause, if available.
     */
    public function __construct($salt, Exception $cause = null)
    {
        $this->salt = $salt;

        parent::__construct(
            sprintf('Invalid salt %s.', var_export($salt, true)),
            0,
            $cause
        );
    }

    /**
     * Get the invalid salt.
     *
     * @return mixed The salt.
     */
    public function salt()
    {
        return $this->salt;
    }

    private $salt;
}
