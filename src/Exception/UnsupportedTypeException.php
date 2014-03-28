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
 * An supported type was encountered.
 */
final class UnsupportedTypeException extends Exception
{
    /**
     * Construct a new unsupported type exception.
     *
     * @param mixed          $type     The unsupported type.
     * @param Exception|null $previous The cause, if available.
     */
    public function __construct($type, Exception $previous = null)
    {
        $this->type = $type;

        parent::__construct(
            sprintf('Unsupported type %s.', var_export($type, true)),
            0,
            $previous
        );
    }

    /**
     * Get the unsupported type.
     *
     * @return mixed The type.
     */
    public function type()
    {
        return $this->type;
    }

    private $type;
}
