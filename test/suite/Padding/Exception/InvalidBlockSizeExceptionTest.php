<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Padding\Exception;

use Exception;
use PHPUnit_Framework_TestCase;

class InvalidBlockSizeExceptionTest extends PHPUnit_Framework_TestCase
{
    public function testException()
    {
        $previous = new Exception;
        $exception = new InvalidBlockSizeException(256, $previous);

        $this->assertSame(256, $exception->blockSize());
        $this->assertSame('Invalid block size 256.', $exception->getMessage());
        $this->assertSame(0, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }
}
