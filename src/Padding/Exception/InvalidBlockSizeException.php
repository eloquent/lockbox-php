<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Padding\Exception;

use Exception;

/**
 * An invalid padding block size was supplied.
 */
final class InvalidBlockSizeException extends Exception
{
    /**
     * Construct a new invalid block size exception.
     *
     * @param mixed          $blockSize The invalid block size.
     * @param Exception|null $previous  The cause, if available.
     */
    public function __construct($blockSize, Exception $previous = null)
    {
        $this->blockSize = $blockSize;

        parent::__construct(
            sprintf('Invalid block size %s.', var_export($blockSize, true)),
            0,
            $previous
        );
    }

    /**
     * Get the invalid block size.
     *
     * @return mixed The block size.
     */
    public function blockSize()
    {
        return $this->blockSize;
    }

    private $blockSize;
}
