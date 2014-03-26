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
 * An supported version was encountered.
 */
final class UnsupportedVersionException extends Exception
{
    /**
     * Construct a new unsupported version exception.
     *
     * @param mixed          $version  The unsupported version.
     * @param Exception|null $previous The cause, if available.
     */
    public function __construct($version, Exception $previous = null)
    {
        $this->version = $version;

        parent::__construct(
            sprintf('Unsupported version %s.', var_export($version, true)),
            0,
            $previous
        );
    }

    /**
     * Get the unsupported version.
     *
     * @return mixed The version.
     */
    public function version()
    {
        return $this->version;
    }

    private $version;
}
