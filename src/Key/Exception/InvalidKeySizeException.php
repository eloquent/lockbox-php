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
 * The key size is invalid.
 */
final class InvalidKeySizeException extends Exception implements
    InvalidKeyExceptionInterface
{
    /**
     * Construct a new invalid key size exception.
     *
     * @param integer        $size     The invalid key size.
     * @param Exception|null $previous The cause, if available.
     */
    public function __construct($size, Exception $previous = null)
    {
        $this->size = $size;

        parent::__construct(
            sprintf(
                'Invalid key size %d. Keys must be 128, 192, or 256 bits.',
                $size
            ),
            0,
            $previous
        );
    }

    /**
     * Get the invalid key size.
     *
     * @return string The size.
     */
    public function size()
    {
        return $this->size;
    }

    private $size;
}
