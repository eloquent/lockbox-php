<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Key;

use Eloquent\Endec\Base64\Base64Url;
use Eloquent\Liberator\Liberator;
use Icecave\Isolator\Isolator;
use PHPUnit_Framework_TestCase;
use Phake;

class KeyWriterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->encoder = new Base64Url;
        $this->isolator = Phake::mock(Isolator::className());
        $this->writer = new KeyWriter($this->encoder, $this->isolator);

        $this->keyFull = new Key(
            '12345678901234567890123456789012',
            '12345678901234567890123456789013',
            'name',
            'description'
        );
        $this->keyMinimal = new Key('1234567890123456', '12345678901234567890123456789013');

        $this->keyFullString = <<<'EOD'
{
    "name": "name",
    "description": "description",
    "type": "lockbox-key",
    "version": 1,
    "encryptionSecret": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI",
    "authenticationSecret": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTM"
}

EOD;
        $this->keyMinimalString = <<<'EOD'
{
    "type": "lockbox-key",
    "version": 1,
    "encryptionSecret": "MTIzNDU2Nzg5MDEyMzQ1Ng",
    "authenticationSecret": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTM"
}

EOD;
    }

    protected function tearDown()
    {
        parent::tearDown();

        if (is_resource($this->stream)) {
            fclose($this->stream);
        }
    }

    public function testConstructor()
    {
        $this->assertSame($this->encoder, $this->writer->encoder());
    }

    public function testConstructorDefaults()
    {
        $this->writer = new KeyWriter;

        $this->assertSame(Base64Url::instance(), $this->writer->encoder());
    }

    public function testWriteFileFull()
    {
        $path = sprintf('%s/%s', sys_get_temp_dir(), uniqid('lockbox-'));
        $this->stream = fopen($path, 'wb');
        Phake::when($this->isolator)->fopen($path, 'wb')->thenReturn($this->stream);
        $this->writer->writeFile($this->keyFull, $path);

        $this->assertSame($this->keyFullString, file_get_contents($path));
        Phake::verify($this->isolator)->fclose($this->stream);
    }

    public function testWriteFileMinimal()
    {
        $path = sprintf('%s/%s', sys_get_temp_dir(), uniqid('lockbox-'));
        $this->stream = fopen($path, 'wb');
        Phake::when($this->isolator)->fopen($path, 'wb')->thenReturn($this->stream);
        $this->writer->writeFile($this->keyMinimal, $path);

        $this->assertSame($this->keyMinimalString, file_get_contents($path));
        Phake::verify($this->isolator)->fclose($this->stream);
    }

    public function testWriteFileFailureStreamOpen()
    {
        Phake::when($this->isolator)->fopen('/path/to/file', 'wb')->thenReturn(false);

        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Exception\KeyWriteException',
            "Unable to write key to '/path/to/file'."
        );
        $this->writer->writeFile($this->keyMinimal, '/path/to/file');
    }

    public function testWriteFileFailureStreamWrite()
    {
        $this->stream = 'foo';
        Phake::when($this->isolator)->fopen('/path/to/file', 'wb')->thenReturn($this->stream);
        $e = null;
        try {
            $this->writer->writeFile($this->keyMinimal, '/path/to/file');
        } catch (Exception\KeyWriteException $e) {
        }

        $this->assertInstanceOf('Eloquent\Lockbox\Key\Exception\KeyWriteException', $e);
        $this->assertSame("Unable to write key to '/path/to/file'.", $e->getMessage());
        Phake::verify($this->isolator)->fclose($this->stream);
    }

    public function testWriteStreamFull()
    {
        $path = sprintf('%s/%s', sys_get_temp_dir(), uniqid('lockbox-'));
        $this->stream = fopen($path, 'wb');
        $this->writer->writeStream($this->keyFull, $this->stream);

        $this->assertSame($this->keyFullString, file_get_contents($path));
    }

    public function testWriteStreamMinimal()
    {
        $path = sprintf('%s/%s', sys_get_temp_dir(), uniqid('lockbox-'));
        $this->stream = fopen($path, 'wb');
        $this->writer->writeStream($this->keyMinimal, $this->stream);

        $this->assertSame($this->keyMinimalString, file_get_contents($path));
    }

    public function testWriteStreamFailureWithPath()
    {
        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Exception\KeyWriteException',
            "Unable to write key to '/path/to/file'."
        );
        $this->writer->writeStream($this->keyMinimal, null, '/path/to/file');
    }

    public function testWriteStreamFailureWithoutPath()
    {
        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Exception\KeyWriteException',
            "Unable to write key to stream."
        );
        $this->writer->writeStream($this->keyMinimal, null);
    }

    public function testWriteStringFull()
    {
        $this->assertSame($this->keyFullString, $this->writer->writeString($this->keyFull));
    }

    public function testWriteStringMinimal()
    {
        $this->assertSame($this->keyMinimalString, $this->writer->writeString($this->keyMinimal));
    }

    public function testInstance()
    {
        $className = get_class($this->writer);
        Liberator::liberateClass($className)->instance = null;
        $instance = $className::instance();

        $this->assertInstanceOf($className, $instance);
        $this->assertSame($instance, $className::instance());
    }

    private $stream;
}
