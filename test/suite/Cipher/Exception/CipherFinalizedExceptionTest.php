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
use Exception;
use PHPUnit_Framework_TestCase;

class CipherFinalizedExceptionTest extends PHPUnit_Framework_TestCase
{
    public function testException()
    {
        $cipher = new EncryptCipher;
        $cause = new Exception;
        $exception = new CipherFinalizedException($cipher, $cause);

        $this->assertSame('The cipher is already finalized.', $exception->getMessage());
        $this->assertSame(0, $exception->getCode());
        $this->assertSame($cause, $exception->getPrevious());
        $this->assertSame($cipher, $exception->cipher());
    }
}
