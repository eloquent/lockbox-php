<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Cipher\Exception;

use Eloquent\Lockbox\Cipher\EncryptCipher;
use Eloquent\Lockbox\Password\Password;
use Exception;
use PHPUnit_Framework_TestCase;

class UnsupportedCipherParametersExceptionTest extends PHPUnit_Framework_TestCase
{
    public function testException()
    {
        $cipher = new EncryptCipher;
        $parameters = new Password('password');
        $cause = new Exception;
        $exception = new UnsupportedCipherParametersException($cipher, $parameters, $cause);

        $this->assertSame(
            "Cipher of type 'Eloquent\\\\Lockbox\\\\Cipher\\\\EncryptCipher' does not support parameters of type " .
            "'Eloquent\\\\Lockbox\\\\Password\\\\Password'.",
            $exception->getMessage()
        );
        $this->assertSame(0, $exception->getCode());
        $this->assertSame($cause, $exception->getPrevious());
        $this->assertSame($cipher, $exception->cipher());
        $this->assertSame($parameters, $exception->parameters());
    }
}
