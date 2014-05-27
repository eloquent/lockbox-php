<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Key\Persistence\Exception;

use Exception;
use PHPUnit_Framework_TestCase;

class KeyWriteExceptionTest extends PHPUnit_Framework_TestCase
{
    public function testException()
    {
        $cause = new Exception;
        $exception = new KeyWriteException('/path/to/file', $cause);

        $this->assertSame('/path/to/file', $exception->path());
        $this->assertSame("Unable to write key to '/path/to/file'.", $exception->getMessage());
        $this->assertSame(0, $exception->getCode());
        $this->assertSame($cause, $exception->getPrevious());
    }

    public function testExceptionDefaults()
    {
        $exception = new KeyWriteException;

        $this->assertNull($exception->path());
        $this->assertSame("Unable to write key to stream.", $exception->getMessage());
        $this->assertSame(0, $exception->getCode());
        $this->assertNull($exception->getPrevious());
    }
}
