<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Cipher\Exception;

use Exception;

/**
 * The cipher is not initialized.
 */
final class CipherNotInitializedException extends Exception implements
    CipherStateExceptionInterface
{
    /**
     * Construct a new cipher not initialized exception.
     *
     * @param Exception|null $previous The cause, if available.
     */
    public function __construct(Exception $previous = null)
    {
        parent::__construct('The cipher is not initialized.', 0, $previous);
    }
}
