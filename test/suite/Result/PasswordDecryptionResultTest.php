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

use PHPUnit_Framework_TestCase;

/**
 * @covers \Eloquent\Lockbox\Result\PasswordDecryptionResult
 * @covers \Eloquent\Lockbox\Result\AbstractDecryptionResult
 */
class PasswordDecryptionResultTest extends PHPUnit_Framework_TestCase
{
    public function testSuccessResult()
    {
        $result = new PasswordDecryptionResult(DecryptionResultType::SUCCESS(), 111);

        $this->assertSame(DecryptionResultType::SUCCESS(), $result->type());
        $this->assertSame(111, $result->iterations());
        $this->assertTrue($result->isSuccessful());
    }

    public function testFailureResult()
    {
        $result = new PasswordDecryptionResult(DecryptionResultType::INVALID_MAC());

        $this->assertSame(DecryptionResultType::INVALID_MAC(), $result->type());
        $this->assertNull($result->iterations());
        $this->assertFalse($result->isSuccessful());
    }
}
