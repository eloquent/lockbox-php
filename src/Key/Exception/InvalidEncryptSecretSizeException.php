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
 * The encrypt secret size is invalid.
 */
final class InvalidEncryptSecretSizeException extends Exception implements
    InvalidKeyParameterExceptionInterface
{
    /**
     * Construct a new invalid encrypt secret size exception.
     *
     * @param integer        $size  The invalid secret size.
     * @param Exception|null $cause The cause, if available.
     */
    public function __construct($size, Exception $cause = null)
    {
        $this->size = $size;

        parent::__construct(
            sprintf(
                'Invalid encrypt secret size %d. ' .
                'Encrypt secret must be 128, 192, or 256 bits.',
                $size
            ),
            0,
            $cause
        );
    }

    /**
     * Get the invalid secret size.
     *
     * @return integer The size.
     */
    public function size()
    {
        return $this->size;
    }

    private $size;
}
