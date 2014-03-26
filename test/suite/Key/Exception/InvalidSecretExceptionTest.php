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

class InvalidSecretExceptionTest extends PHPUnit_Framework_TestCase
{
    public function testException()
    {
        $cause = new Exception;
        $exception = new InvalidSecretException('secret', $cause);

        $this->assertSame('secret', $exception->secret());
        $this->assertSame("Invalid secret 'secret'.", $exception->getMessage());
        $this->assertSame(0, $exception->getCode());
        $this->assertSame($cause, $exception->getPrevious());
    }
}
