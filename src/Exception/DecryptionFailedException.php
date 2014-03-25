<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Exception;

use Exception;

/**
 * Decryption failed.
 */
final class DecryptionFailedException extends Exception
{
    /**
     * Construct a new decryption failed exception.
     *
     * @param Exception|null $previous The cause, if available.
     */
    public function __construct(Exception $previous = null)
    {
        parent::__construct('Decryption failed.', 0, $previous);
    }
}
