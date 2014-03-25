<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Exception;

use Eloquent\Lockbox\Key\Key;
use Exception;
use PHPUnit_Framework_TestCase;

class DecryptionFailedExceptionTest extends PHPUnit_Framework_TestCase
{
    public function testException()
    {
        $key = new Key('1234567890123456', 'name');
        $previous = new Exception;
        $exception = new DecryptionFailedException($key, $previous);

        $this->assertSame($key, $exception->key());
        $this->assertSame("Decryption failed for key 'name'.", $exception->getMessage());
        $this->assertSame(0, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }

    public function testExceptionNoKeyName()
    {
        $key = new Key('1234567890123456');
        $previous = new Exception;
        $exception = new DecryptionFailedException($key, $previous);

        $this->assertSame($key, $exception->key());
        $this->assertSame("Decryption failed.", $exception->getMessage());
        $this->assertSame(0, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }
}
