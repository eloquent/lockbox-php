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

class KeyReaderTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->factory = new KeyFactory;
        $this->base64UrlDecoder = new Base64Url;
        $this->isolator = Phake::mock(Isolator::className());
        $this->reader = new KeyReader($this->factory, $this->base64UrlDecoder, $this->isolator);

        $this->jsonDataFull = <<<'EOD'
{
    "type": "lockbox-key",
    "version": 1,
    "name": "name",
    "description": "description",
    "key": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI"
}
EOD;
        $this->jsonDataMinimal = '{"type":"lockbox-key","version":1,"key":"MTIzNDU2Nzg5MDEyMzQ1Ng"}';
    }

    public function testConstructor()
    {
        $this->assertSame($this->factory, $this->reader->factory());
        $this->assertSame($this->base64UrlDecoder, $this->reader->base64UrlDecoder());
    }

    public function testConstructorDefaults()
    {
        $this->reader = new KeyReader;

        $this->assertSame(KeyFactory::instance(), $this->reader->factory());
        $this->assertSame(Base64Url::instance(), $this->reader->base64UrlDecoder());
    }

    public function testReadFileFull()
    {
        $stream = fopen('data://text/plain;base64,' . base64_encode($this->jsonDataFull), 'rb');
        Phake::when($this->isolator)->fopen('/path/to/file', 'rb')->thenReturn($stream);
        $key = $this->reader->readFile('/path/to/file');

        $this->assertSame('12345678901234567890123456789012', $key->data());
        $this->assertSame('name', $key->name());
        $this->assertSame('description', $key->description());
        Phake::verify($this->isolator)->fclose($stream);
    }

    public function testReadFileMinimal()
    {
        $stream = fopen('data://text/plain;base64,' . base64_encode($this->jsonDataMinimal), 'rb');
        Phake::when($this->isolator)->fopen('/path/to/file', 'rb')->thenReturn($stream);
        $key = $this->reader->readFile('/path/to/file');

        $this->assertSame('1234567890123456', $key->data());
        $this->assertNull($key->name());
        $this->assertNull($key->description());
        Phake::verify($this->isolator)->fclose($stream);
    }

    public function testReadFileFailureStreamOpen()
    {
        Phake::when($this->isolator)->fopen('/path/to/file', 'rb')->thenReturn(false);

        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Exception\KeyReadException',
            "Unable to read key from '/path/to/file'."
        );
        $this->reader->readFile('/path/to/file');
    }

    public function testReadFileFailureInvalidKey()
    {
        $stream = fopen('data://text/plain;base64,' . base64_encode('{'), 'rb');
        Phake::when($this->isolator)->fopen('/path/to/file', 'rb')->thenReturn($stream);
        $e = null;
        try {
            $this->reader->readFile('/path/to/file');
        } catch (Exception\KeyReadException $e) {
        }

        $this->assertInstanceOf('Eloquent\Lockbox\Key\Exception\KeyReadException', $e);
        $this->assertSame("Unable to read key from '/path/to/file'.", $e->getMessage());
        Phake::verify($this->isolator)->fclose($stream);
    }

    public function testReadStreamFull()
    {
        $stream = fopen('data://text/plain;base64,' . base64_encode($this->jsonDataFull), 'rb');
        $key = $this->reader->readStream($stream);

        $this->assertSame('12345678901234567890123456789012', $key->data());
        $this->assertSame('name', $key->name());
        $this->assertSame('description', $key->description());
    }

    public function testReadStreamMinimal()
    {
        $stream = fopen('data://text/plain;base64,' . base64_encode($this->jsonDataMinimal), 'rb');
        $key = $this->reader->readStream($stream);

        $this->assertSame('1234567890123456', $key->data());
        $this->assertNull($key->name());
        $this->assertNull($key->description());
    }

    public function testReadStreamFailureStreamReadWithoutPath()
    {
        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Exception\KeyReadException',
            "Unable to read key from stream."
        );
        $this->reader->readStream(null);
    }

    public function testReadStreamFailureStreamReadWithPath()
    {
        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Exception\KeyReadException',
            "Unable to read key from '/path/to/file'."
        );
        $this->reader->readStream(null, '/path/to/file');
    }

    public function invalidDataData()
    {
        return array(
            'Invalid JSON'        => array('{'),
            'Missing type'        => array('{"version":1,"key":"MTIzNDU2Nzg5MDEyMzQ1Ng"}'),
            'Invalid type'        => array('{"type":"lockbox-foo","version":1,"key":"MTIzNDU2Nzg5MDEyMzQ1Ng"}'),
            'Missing version'     => array('{"type":"lockbox-key","key":"MTIzNDU2Nzg5MDEyMzQ1Ng"}'),
            'Invalid version'     => array('{"type":"lockbox-key","version":"1","key":"MTIzNDU2Nzg5MDEyMzQ1Ng"}'),
            'Missing data'        => array('{"type":"lockbox-key","version":1}'),
            'Invalid base64 data' => array('{"type":"lockbox-key","version":1,"key":"MTIzNDU2Nzg5MDEyMzQ1N"}'),
            'Invalid key data'    => array('{"type":"lockbox-key","version":1,"key":"MTIzNDU2"}'),
        );
    }

    /**
     * @dataProvider invalidDataData
     */
    public function testReadStreamFailureInvalidDataWithoutPath($jsonData)
    {
        $stream = fopen('data://text/plain;base64,' . base64_encode($jsonData), 'rb');

        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Exception\KeyReadException',
            "Unable to read key from stream."
        );
        $this->reader->readStream($stream);
    }

    /**
     * @dataProvider invalidDataData
     */
    public function testReadStreamFailureInvalidDataWithPath($jsonData)
    {
        $stream = fopen('data://text/plain;base64,' . base64_encode($jsonData), 'rb');

        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Exception\KeyReadException',
            "Unable to read key from '/path/to/file'."
        );
        $this->reader->readStream($stream, '/path/to/file');
    }

    public function testInstance()
    {
        $className = get_class($this->reader);
        Liberator::liberateClass($className)->instance = null;
        $instance = $className::instance();

        $this->assertInstanceOf($className, $instance);
        $this->assertSame($instance, $className::instance());
    }
}
