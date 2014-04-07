<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Result;

use Eloquent\Liberator\Liberator;
use PHPUnit_Framework_TestCase;

class DecryptionResultTypeTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        Liberator::liberateClass('Eloquent\Lockbox\Result\DecryptionResultType')->members = array();
    }

    public function typeData()
    {
        //                                 key                    isSuccessful
        return array(
            'Success'             => array('SUCCESS',             true),

            'Insufficient data'   => array('INSUFFICIENT_DATA',   false),
            'Invalid MAC'         => array('INVALID_MAC',         false),
            'Unsupported version' => array('UNSUPPORTED_VERSION', false),
            'Unsupported type'    => array('UNSUPPORTED_TYPE',    false),
            'Invalid padding'     => array('INVALID_PADDING',     false),
        );
    }

    /**
     * @dataProvider typeData
     */
    public function testTypes($key, $isSuccessful)
    {
        $this->assertSame($isSuccessful, DecryptionResultType::memberByKey($key)->isSuccessful());
    }
}
