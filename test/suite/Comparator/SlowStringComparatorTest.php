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

use PHPUnit_Framework_TestCase;

class SlowStringComparatorTest extends PHPUnit_Framework_TestCase
{
    public function isEqualData()
    {
        //                            left   right
        return array(
            'Equal'          => array('foo', 'foo'),
            'Greater than'   => array('foo', 'bar'),
            'Less than'      => array('bar', 'foo'),
            'Length greater' => array('foo', 'fo'),
            'Length lesser'  => array('foo', 'fooo'),
        );
    }

    /**
     * @dataProvider isEqualData
     */
    public function testIsEqual($left, $right)
    {
        $this->assertSame($left === $right, SlowStringComparator::isEqual($left, $right));
    }
}
