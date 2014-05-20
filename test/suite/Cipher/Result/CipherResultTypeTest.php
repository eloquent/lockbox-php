<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Cipher\Result;

use Eloquent\Liberator\Liberator;
use PHPUnit_Framework_TestCase;

class CipherResultTypeTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        Liberator::liberateClass('Eloquent\Lockbox\Cipher\Result\CipherResultType')->members = array();
    }

    public function testMultiton()
    {
        $this->assertTrue(CipherResultType::SUCCESS()->isSuccessful());

        $this->assertFalse(CipherResultType::INVALID_SIZE()->isSuccessful());
        $this->assertFalse(CipherResultType::INVALID_ENCODING()->isSuccessful());
        $this->assertFalse(CipherResultType::INVALID_MAC()->isSuccessful());
        $this->assertFalse(CipherResultType::UNSUPPORTED_VERSION()->isSuccessful());
        $this->assertFalse(CipherResultType::UNSUPPORTED_TYPE()->isSuccessful());
        $this->assertFalse(CipherResultType::INVALID_PADDING()->isSuccessful());
        $this->assertFalse(CipherResultType::TOO_MANY_ITERATIONS()->isSuccessful());
    }
}
