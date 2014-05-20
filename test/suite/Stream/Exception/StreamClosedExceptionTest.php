<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Stream\Exception;

use Eloquent\Lockbox\Cipher\EncryptCipher;
use Eloquent\Lockbox\Stream\CipherStream;
use Exception;
use PHPUnit_Framework_TestCase;

class StreamClosedExceptionTest extends PHPUnit_Framework_TestCase
{
    public function testException()
    {
        $stream = new CipherStream(new EncryptCipher);
        $cause = new Exception;
        $exception = new StreamClosedException($stream, $cause);

        $this->assertSame($stream, $exception->stream());
        $this->assertSame("The stream is closed.", $exception->getMessage());
        $this->assertSame(0, $exception->getCode());
        $this->assertSame($cause, $exception->getPrevious());
    }
}
