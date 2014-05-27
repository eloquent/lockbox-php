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

class KeyReadExceptionTest extends PHPUnit_Framework_TestCase
{
    public function testException()
    {
        $cause = new Exception;
        $exception = new KeyReadException('/path/to/file', $cause);

        $this->assertSame('/path/to/file', $exception->path());
        $this->assertSame("Unable to read key from '/path/to/file'.", $exception->getMessage());
        $this->assertSame(0, $exception->getCode());
        $this->assertSame($cause, $exception->getPrevious());
    }

    public function testExceptionDefaults()
    {
        $exception = new KeyReadException;

        $this->assertNull($exception->path());
        $this->assertSame("Unable to read key.", $exception->getMessage());
        $this->assertSame(0, $exception->getCode());
        $this->assertNull($exception->getPrevious());
    }
}
