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
 * Could not read a key from the specified path or stream.
 */
final class KeyReadException extends Exception
{
    /**
     * Construct a new key read exception.
     *
     * @param string|null    $path  The path, if known.
     * @param Exception|null $cause The cause, if available.
     */
    public function __construct($path = null, Exception $cause = null)
    {
        $this->path = $path;

        if (null === $path) {
            $message = 'Unable to read key from stream.';
        } else {
            $message = sprintf(
                'Unable to read key from %s.',
                var_export($path, true)
            );
        }

        parent::__construct($message, 0, $cause);
    }

    /**
     * Get the path.
     *
     * @return string|null The path, if known.
     */
    public function path()
    {
        return $this->path;
    }

    private $path;
}
