<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Password\Cipher\Result;

use Eloquent\Lockbox\Cipher\Result\CipherResultType;
use Eloquent\Lockbox\Password\Password;
use PHPUnit_Framework_TestCase;

/**
 * @covers \Eloquent\Lockbox\Password\Cipher\Result\PasswordDecryptResult
 * @covers \Eloquent\Lockbox\Cipher\Result\AbstractCipherResult
 */
class PasswordDecryptResultTest extends PHPUnit_Framework_TestCase
{
    public function testSuccessResult()
    {
        $result = new PasswordDecryptResult(CipherResultType::SUCCESS(), 111);

        $this->assertSame(CipherResultType::SUCCESS(), $result->type());
        $this->assertTrue($result->isSuccessful());
        $this->assertSame(111, $result->iterations());
        $this->assertNull($result->data());
    }

    public function testFailureResult()
    {
        $result = new PasswordDecryptResult(CipherResultType::INVALID_MAC());

        $this->assertSame(CipherResultType::INVALID_MAC(), $result->type());
        $this->assertFalse($result->isSuccessful());
        $this->assertNull($result->iterations());
        $this->assertNull($result->data());
    }

    public function testConstructorData()
    {
        $result = new PasswordDecryptResult(CipherResultType::SUCCESS(), 111, 'foo');

        $this->assertSame('foo', $result->data());
    }

    public function testSetData()
    {
        $result = new PasswordDecryptResult(CipherResultType::SUCCESS(), 111);
        $result->setData('foo');

        $this->assertSame('foo', $result->data());
    }

    public function testSetIterations()
    {
        $result = new PasswordDecryptResult(CipherResultType::SUCCESS());
        $result->setIterations(111);

        $this->assertSame(111, $result->iterations());
    }
}
