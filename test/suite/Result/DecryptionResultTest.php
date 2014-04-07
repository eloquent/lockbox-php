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

class DecryptionResultTest extends PHPUnit_Framework_TestCase
{
    public function testSuccessResult()
    {
        $result = new DecryptionResult(DecryptionResultType::SUCCESS());

        $this->assertSame(DecryptionResultType::SUCCESS(), $result->type());
        $this->assertTrue($result->isSuccessful());
    }
}
