<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Random;

use Icecave\Isolator\Isolator;

/**
 * A random data source for /dev/urandom.
 */
class DevUrandom extends AbstractMcryptRandomSource
{
    /**
     * Get the static instance of this random source.
     *
     * @return RandomSourceInterface The static random source.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new /dev/urandom random source.
     *
     * @param Isolator|null $isolator The isolator to use.
     */
    public function __construct(Isolator $isolator = null)
    {
        parent::__construct(MCRYPT_DEV_URANDOM, $isolator);
    }

    private static $instance;
}
