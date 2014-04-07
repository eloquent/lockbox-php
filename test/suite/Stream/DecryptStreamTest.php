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
use Eloquent\Lockbox\Result\DecryptionResult;
use Eloquent\Lockbox\Result\DecryptionResultType;
use PHPUnit_Framework_TestCase;
use Phake;

class DecryptStreamTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->decodeTransform = Phake::mock('Eloquent\Confetti\TransformInterface');
        $this->decryptTransform = Phake::mock('Eloquent\Lockbox\Transform\DecryptTransformInterface');
        $this->stream = new DecryptStream(
            new CompoundTransform(array($this->decodeTransform, $this->decryptTransform))
        );
    }

    public function testResult()
    {
        $this->result = new DecryptionResult(DecryptionResultType::INVALID_MAC());
        Phake::when($this->decryptTransform)->result()->thenReturn(null)->thenReturn($this->result);

        $this->assertNull($this->stream->result());
        $this->assertSame($this->result, $this->stream->result());
    }
}
