<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox;

use Icecave\Isolator\Isolator;

/**
 * A static utility class for registering stream filters.
 */
abstract class Lockbox
{
    /**
     * Register Lockbox's stream filters.
     *
     * @param Isolator|null $isolator The isolator to use.
     */
    public static function registerFilters(Isolator $isolator = null)
    {
        $isolator = Isolator::get($isolator);

        $isolator->stream_filter_register(
            'lockbox.encrypt-raw',
            'Eloquent\Lockbox\Stream\Filter\RawEncryptStreamFilter'
        );
        $isolator->stream_filter_register(
            'lockbox.decrypt-raw',
            'Eloquent\Lockbox\Stream\Filter\RawDecryptStreamFilter'
        );
    }
}
