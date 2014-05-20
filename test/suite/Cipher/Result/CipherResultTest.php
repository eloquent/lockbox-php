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

use PHPUnit_Framework_TestCase;

/**
 * @covers \Eloquent\Lockbox\Cipher\Result\CipherResult
 * @covers \Eloquent\Lockbox\Cipher\Result\AbstractCipherResult
 */
class CipherResultTest extends PHPUnit_Framework_TestCase
{
    public function testSuccessResult()
    {
        $result = new CipherResult(CipherResultType::SUCCESS());

        $this->assertSame(CipherResultType::SUCCESS(), $result->type());
        $this->assertTrue($result->isSuccessful());
        $this->assertNull($result->data());
    }

    public function testFailureResult()
    {
        $result = new CipherResult(CipherResultType::INVALID_MAC());

        $this->assertSame(CipherResultType::INVALID_MAC(), $result->type());
        $this->assertFalse($result->isSuccessful());
        $this->assertNull($result->data());
    }

    public function testConstructorData()
    {
        $result = new CipherResult(CipherResultType::SUCCESS(), 'foo');

        $this->assertSame('foo', $result->data());
    }

    public function testSetData()
    {
        $result = new CipherResult(CipherResultType::SUCCESS());
        $result->setData('foo');

        $this->assertSame('foo', $result->data());
    }
}
