<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Exception;

use Exception;

/**
 * Invalid encoding was detected.
 */
final class InvalidEncodingException extends Exception
{
    /**
     * Construct a new invalid encoding exception.
     *
     * @param Exception|null $previous The cause, if available.
     */
    public function __construct(Exception $previous = null)
    {
        parent::__construct('Invalid encoding.', 0, $previous);
    }
}
