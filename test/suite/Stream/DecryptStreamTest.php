<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Stream;

use Eloquent\Confetti\CompoundTransform;
use Eloquent\Lockbox\Cipher\Result\CipherResult;
use Eloquent\Lockbox\Cipher\Result\CipherResultType;
use PHPUnit_Framework_TestCase;
use Phake;

class DecryptStreamTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->decodeTransform = Phake::mock('Eloquent\Confetti\TransformInterface');
        $this->cipherTransform = Phake::mock('Eloquent\Lockbox\Transform\CipherTransformInterface');
        $this->stream = new DecryptStream(
            new CompoundTransform(array($this->decodeTransform, $this->cipherTransform))
        );
    }

    public function testResult()
    {
        $this->result = new CipherResult(CipherResultType::INVALID_MAC());
        Phake::when($this->cipherTransform)->result()->thenReturn(null)->thenReturn($this->result);

        $this->assertNull($this->stream->result());
        $this->assertSame($this->result, $this->stream->result());
    }
}
