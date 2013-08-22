<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Key\Exception;

use Exception;

/**
 * The requested detail is not present.
 */
final class MissingDetailException extends Exception
{
    /**
     * Construct a new missing detail exception.
     *
     * @param string         $name     The name of the requested detail.
     * @param Exception|null $previous The cause, if available.
     */
    public function __construct($name, Exception $previous = null)
    {
        $this->name = $name;

        parent::__construct(
            sprintf('Missing key detail %s.', var_export($name, true)),
            0,
            $previous
        );
    }

    /**
     * Get the detail name.
     *
     * @return string The detail name.
     */
    public function name()
    {
        return $this->name;
    }

    private $name;
}
