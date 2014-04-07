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
 * @covers \Eloquent\Lockbox\Result\DecryptionResult
 * @covers \Eloquent\Lockbox\Result\AbstractDecryptionResult
 */
class DecryptionResultTest extends PHPUnit_Framework_TestCase
{
    public function testSuccessResult()
    {
        $result = new DecryptionResult(DecryptionResultType::SUCCESS(), 'data');

        $this->assertSame(DecryptionResultType::SUCCESS(), $result->type());
        $this->assertTrue($result->isSuccessful());
        $this->assertSame('data', $result->data());
    }

    public function testFailureResult()
    {
        $result = new DecryptionResult(DecryptionResultType::INVALID_MAC());

        $this->assertSame(DecryptionResultType::INVALID_MAC(), $result->type());
        $this->assertFalse($result->isSuccessful());
        $this->assertNull($result->data());
    }
}
