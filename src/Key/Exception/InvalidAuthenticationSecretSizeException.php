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
 * The authentication secret size is invalid.
 */
final class InvalidAuthenticationSecretSizeException extends Exception implements
    InvalidKeyExceptionInterface
{
    /**
     * Construct a new invalid authentication secret size exception.
     *
     * @param integer        $size     The invalid secret size.
     * @param Exception|null $previous The cause, if available.
     */
    public function __construct($size, Exception $previous = null)
    {
        $this->size = $size;

        parent::__construct(
            sprintf(
                'Invalid authentication secret size %d. ' .
                'Authentication secret must be 224, 256, 384, or 512 bits.',
                $size
            ),
            0,
            $previous
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
