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

use Eloquent\Endec\Base64\Base64Url;
use Eloquent\Lockbox\Cipher\DecryptCipher;
use Eloquent\Lockbox\Cipher\EncryptCipher;
use Eloquent\Lockbox\Cipher\Parameters\EncryptParameters;
use Eloquent\Lockbox\Cipher\Result\CipherResult;
use Eloquent\Lockbox\Cipher\Result\CipherResultType;
use Eloquent\Lockbox\Key\Key;
use Eloquent\Lockbox\RawEncrypter;
use Eloquent\Lockbox\Stream\Exception\StreamClosedException;
use Eloquent\Lockbox\Test\TestWritableStream;
use PHPUnit_Framework_TestCase;

class CipherStreamTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->decryptParameters = new Key('1234567890123456', '1234567890123456789012345678');
        $this->encryptParameters = new EncryptParameters($this->decryptParameters, '1234567890123456');
        $this->cipher = new EncryptCipher;
        $this->cipher->initialize($this->encryptParameters);
        $this->stream = new CipherStream($this->cipher);

        $this->base64url = new Base64Url;

        $this->setUpEvents();
    }

    protected function setUpEvents()
    {
        $self = $this;
        $this->datasEmitted = $this->endsEmitted = $this->closesEmitted = $this->successesEmitted = 0;
        $this->output = '';
        $this->errors = array();

        $this->stream->on(
            'data',
            function ($data, $stream) use ($self) {
                $self->datasEmitted ++;
                $self->output .= $data;
            }
        );
        $this->stream->on(
            'end',
            function ($codec) use ($self) {
                $self->endsEmitted++;
            }
        );
        $this->stream->on(
            'close',
            function ($codec) use ($self) {
                $self->closesEmitted ++;
            }
        );
        $this->stream->on(
            'success',
            function ($codec) use ($self) {
                $self->successesEmitted ++;
            }
        );
        $this->stream->on(
            'error',
            function ($error, $codec) use ($self) {
                $self->errors[] = $error;
            }
        );
    }

    public function testConstructor()
    {
        $this->assertSame($this->cipher, $this->stream->cipher());
    }

    public function testWriteEnd()
    {
        $writeReturn = $this->stream->write('foobarbazquxdoom');
        $this->stream->end();

        $this->assertTrue($writeReturn);
        $this->assertSame(
            'AQExMjM0NTY3ODkwMTIzNDU2T5xLPdYzBeLJW8xyiDdJlARuymJY90WHKOgcF23ibdyk566-sQjw5FuvnO4d9gtDqlneP8If-xnEoIZdg-yvkg',
            $this->base64url->encode($this->output)
        );
        $this->assertSame(2, $this->datasEmitted);
        $this->assertSame(1, $this->endsEmitted);
        $this->assertSame(1, $this->closesEmitted);
        $this->assertSame(1, $this->successesEmitted);
    }

    public function testWriteEndEmpty()
    {
        $writeReturn = $this->stream->write('');
        $this->stream->end();

        $this->assertTrue($writeReturn);
        $this->assertSame(
            'AQExMjM0NTY3ODkwMTIzNDU2BsV8no6a9yLYUT6rbu2PdNC4LItQ9m-F9dQ65M-pun4OnZkLrHT8zDDw0sE4Dg',
            $this->base64url->encode($this->output)
        );
        $this->assertSame(2, $this->datasEmitted);
        $this->assertSame(1, $this->endsEmitted);
        $this->assertSame(1, $this->closesEmitted);
        $this->assertSame(1, $this->successesEmitted);
    }

    public function testEnd()
    {
        $this->stream->end('foobarbazquxdoom');

        $this->assertSame(
            'AQExMjM0NTY3ODkwMTIzNDU2T5xLPdYzBeLJW8xyiDdJlARuymJY90WHKOgcF23ibdyk566-sQjw5FuvnO4d9gtDqlneP8If-xnEoIZdg-yvkg',
            $this->base64url->encode($this->output)
        );
        $this->assertSame(1, $this->datasEmitted);
        $this->assertSame(1, $this->endsEmitted);
        $this->assertSame(1, $this->closesEmitted);
        $this->assertSame(1, $this->successesEmitted);
    }

    public function testEndEmpty()
    {
        $this->stream->end('');

        $this->assertSame(
            'AQExMjM0NTY3ODkwMTIzNDU2BsV8no6a9yLYUT6rbu2PdNC4LItQ9m-F9dQ65M-pun4OnZkLrHT8zDDw0sE4Dg',
            $this->base64url->encode($this->output)
        );
        $this->assertSame(1, $this->datasEmitted);
        $this->assertSame(1, $this->endsEmitted);
        $this->assertSame(1, $this->closesEmitted);
        $this->assertSame(1, $this->successesEmitted);
    }

    public function testClose()
    {
        $this->assertTrue($this->stream->isWritable());
        $this->assertTrue($this->stream->isReadable());

        $this->stream->write('foobarbazquxdoom');
        $this->stream->close();
        $this->stream->close();
        $this->stream->end('foobarbazquxdoom');

        $this->assertFalse($this->stream->isWritable());
        $this->assertFalse($this->stream->isReadable());
        $this->assertFalse($this->stream->write('foobarbazquxdoom'));
        $this->assertSame('AQExMjM0NTY3ODkwMTIzNDU2T5xLPdYzBeLJW8xyiDdJlARu', $this->base64url->encode($this->output));
        $this->assertSame(1, $this->datasEmitted);
        $this->assertSame(1, $this->endsEmitted);
        $this->assertSame(1, $this->closesEmitted);
        $this->assertSame(1, $this->successesEmitted);
        $this->assertEquals(array(new StreamClosedException($this->stream)), $this->errors);
    }

    public function testPauseResume()
    {
        $this->stream->pause();

        $this->assertFalse($this->stream->write('foobar'));
        $this->assertSame('', $this->base64url->encode($this->output));

        $this->stream->resume();

        $this->assertTrue($this->stream->write('bazqux'));
        $this->assertSame('AQExMjM0NTY3ODkwMTIzNDU2', $this->base64url->encode($this->output));

        $this->stream->end('doom');

        $this->assertSame(
            'AQExMjM0NTY3ODkwMTIzNDU2T5xLPdYzBeLJW8xyiDdJlARuymJY90WHKOgcF23ibdyk566-sQjw5FuvnO4d9gtDqlneP8If-xnEoIZdg-yvkg',
            $this->base64url->encode($this->output)
        );
    }

    public function testPipe()
    {
        $destination = new TestWritableStream;
        $this->stream->pipe($destination);
        $this->stream->end('foobarbazquxdoom');

        $this->assertSame(
            'AQExMjM0NTY3ODkwMTIzNDU2T5xLPdYzBeLJW8xyiDdJlARuymJY90WHKOgcF23ibdyk566-sQjw5FuvnO4d9gtDqlneP8If-xnEoIZdg-yvkg',
            $this->base64url->encode($destination->data)
        );
    }

    public function testStreamFailure()
    {
        $ciphertext = RawEncrypter::instance()->encrypt(
            $this->encryptParameters,
            'foobarbazquxdoomfoobarbazquxdoomfoobarbazquxdoomfoobarbazquxdoom'
        );
        $ciphertext[89] = '1';
        $ciphertext[90] = '2';
        $this->cipher = new DecryptCipher;
        $this->cipher->initialize($this->decryptParameters);
        $this->stream = new CipherStream($this->cipher);
        $this->setUpEvents();
        $errorA = new CipherResult(CipherResultType::INVALID_MAC());
        $errorB = new StreamClosedException($this->stream);
        $writeReturn = $this->stream->write(substr($ciphertext, 0, 90));

        $this->assertTrue($writeReturn);
        $this->assertSame('foobarbazquxdoom', $this->output);
        $this->assertSame(1, $this->datasEmitted);
        $this->assertSame(0, $this->endsEmitted);
        $this->assertSame(0, $this->closesEmitted);
        $this->assertSame(array(), $this->errors);

        $writeReturn = $this->stream->write(substr($ciphertext, -28));

        $this->assertTrue($writeReturn);
        $this->assertSame('foobarbazquxdoomfoobarbazquxdoomfoobarbazquxdoom', $this->output);
        $this->assertSame(2, $this->datasEmitted);
        $this->assertSame(0, $this->endsEmitted);
        $this->assertSame(0, $this->closesEmitted);
        $this->assertSame(array(), $this->errors);

        $writeReturn = $this->stream->write('foobarbazquxdoomfoobarbazquxdoom');

        $this->assertFalse($writeReturn);
        $this->assertSame('foobarbazquxdoomfoobarbazquxdoomfoobarbazquxdoomfoobarbazquxdoom', $this->output);
        $this->assertSame(3, $this->datasEmitted);
        $this->assertSame(1, $this->endsEmitted);
        $this->assertSame(1, $this->closesEmitted);
        $this->assertEquals(array($errorA), $this->errors);

        $writeReturn = $this->stream->write('foobarbazquxdoomfoobarbazquxdoom');

        $this->assertFalse($writeReturn);
        $this->assertSame('foobarbazquxdoomfoobarbazquxdoomfoobarbazquxdoomfoobarbazquxdoom', $this->output);
        $this->assertSame(3, $this->datasEmitted);
        $this->assertSame(1, $this->endsEmitted);
        $this->assertSame(1, $this->closesEmitted);
        $this->assertEquals(array($errorA, $errorB), $this->errors);

        $this->stream->end();

        $this->assertSame('foobarbazquxdoomfoobarbazquxdoomfoobarbazquxdoomfoobarbazquxdoom', $this->output);
        $this->assertSame(3, $this->datasEmitted);
        $this->assertSame(1, $this->endsEmitted);
        $this->assertSame(1, $this->closesEmitted);
        $this->assertEquals(array($errorA, $errorB), $this->errors);
    }

    public function testStreamFailureOnEnd()
    {
        $ciphertext = RawEncrypter::instance()->encrypt(
            $this->encryptParameters,
            'foobarbazquxdoomfoobarbazquxdoomfoobarbazquxdoomfoobarbazquxdoom'
        );
        $ciphertext[89] = '1';
        $ciphertext[90] = '2';
        $this->cipher = new DecryptCipher;
        $this->cipher->initialize($this->decryptParameters);
        $this->stream = new CipherStream($this->cipher);
        $this->setUpEvents();
        $error = new CipherResult(CipherResultType::INVALID_MAC());
        $this->stream->end($ciphertext);

        $this->assertSame('', $this->output);
        $this->assertSame(0, $this->datasEmitted);
        $this->assertSame(1, $this->endsEmitted);
        $this->assertSame(1, $this->closesEmitted);
        $this->assertEquals(array($error), $this->errors);
    }
}
