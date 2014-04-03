<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Comparator;

/**
 * A constant-time string comparison implementation.
 */
final class SlowStringComparator
{
    /**
     * Compare the supplied strings in constant-time.
     *
     * @param string $left  The left string.
     * @param string $right The right string.
     *
     * @return boolean True if the strings are equal.
     */
    public static function isEqual($left, $right)
    {
        $diff = strlen($left) ^ strlen($right);
        for ($i = 0; $i < strlen($left) && $i < strlen($right); $i++) {
            $diff |= ord($left[$i]) ^ ord($right[$i]);
        }

        return 0 === $diff;
    }
}
