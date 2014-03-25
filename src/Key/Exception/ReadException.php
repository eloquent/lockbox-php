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
 * Could not read from the specified path.
 */
final class ReadException extends Exception
{
    /**
     * Construct a new read exception.
     *
     * @param string         $path     The unreadable path.
     * @param Exception|null $previous The cause, if available.
     */
    public function __construct($path, Exception $previous = null)
    {
        $this->path = $path;

        parent::__construct(
            sprintf('Unable to read from %s.', var_export($path, true)),
            0,
            $previous
        );
    }

    /**
     * Get the path.
     *
     * @return string The path.
     */
    public function path()
    {
        return $this->path;
    }

    private $path;
}
