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

use Eloquent\Lockbox\Cipher\Result\CipherResult;
use Eloquent\Lockbox\Cipher\Result\CipherResultType;
use PHPUnit_Framework_TestCase;
use Phake;

class CompositePreCipherStreamTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->cipher = Phake::mock('Eloquent\Lockbox\Cipher\CipherInterface');
        $this->cipherStream = new CipherStream($this->cipher);
        $this->writable = Phake::mock('React\Stream\WritableStreamInterface');
        $this->stream = new CompositePreCipherStream($this->cipherStream, $this->writable);

        $this->result = new CipherResult(CipherResultType::SUCCESS());

        Phake::when($this->cipher)->result()->thenReturn($this->result);
    }

    public function testConstructor()
    {
        $this->assertSame($this->cipherStream, $this->stream->cipherStream());
        $this->assertSame($this->writable, $this->stream->writable());
        $this->assertSame($this->cipher, $this->stream->cipher());
        $this->assertSame($this->result, $this->stream->result());
    }
}
