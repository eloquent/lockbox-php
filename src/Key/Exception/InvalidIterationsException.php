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
 * The number of iterations is invalid.
 */
final class InvalidIterationsException extends Exception implements
    InvalidKeyParameterExceptionInterface
{
    /**
     * Construct a new invalid iterations exception.
     *
     * @param mixed          $iterations The invalid iterations.
     * @param Exception|null $previous   The cause, if available.
     */
    public function __construct($iterations, Exception $previous = null)
    {
        $this->iterations = $iterations;

        parent::__construct(
            sprintf('Invalid iterations %s.', var_export($iterations, true)),
            0,
            $previous
        );
    }

    /**
     * Get the invalid iterations.
     *
     * @return mixed The iterations.
     */
    public function iterations()
    {
        return $this->iterations;
    }

    private $iterations;
}
