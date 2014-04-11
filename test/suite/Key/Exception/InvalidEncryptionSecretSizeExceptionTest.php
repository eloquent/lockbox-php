<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Key\Exception;

use Exception;
use PHPUnit_Framework_TestCase;

class InvalidEncryptionSecretSizeExceptionTest extends PHPUnit_Framework_TestCase
{
    public function testException()
    {
        $cause = new Exception;
        $exception = new InvalidEncryptionSecretSizeException(111, $cause);

        $this->assertSame(111, $exception->size());
        $this->assertSame(
            "Invalid encryption secret size 111. Encryption secret must be 128, 192, or 256 bits.",
            $exception->getMessage()
        );
        $this->assertSame(0, $exception->getCode());
        $this->assertSame($cause, $exception->getPrevious());
    }
}
