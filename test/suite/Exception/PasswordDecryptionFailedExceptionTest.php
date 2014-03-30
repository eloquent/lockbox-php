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

use Exception;
use PHPUnit_Framework_TestCase;

class PasswordDecryptionFailedExceptionTest extends PHPUnit_Framework_TestCase
{
    public function testException()
    {
        $previous = new Exception;
        $exception = new PasswordDecryptionFailedException('password', $previous);

        $this->assertSame('password', $exception->password());
        $this->assertSame('Password decryption failed.', $exception->getMessage());
        $this->assertSame(0, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }
}
