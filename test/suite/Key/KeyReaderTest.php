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
        $this->decoder = new Base64Url;
        $this->isolator = Phake::mock(Isolator::className());
        $this->reader = new KeyReader($this->factory, $this->decoder, $this->isolator);

        $this->jsonDataFull = <<<'EOD'
{
    "type": "lockbox-key",
    "version": 1,
    "name": "name",
    "description": "description",
    "encryptionSecret": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI",
    "authenticationSecret": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTM"
}
EOD;
        $this->jsonDataMinimal = '{"type":"lockbox-key","version":1,"encryptionSecret":"MTIzNDU2Nzg5MDEyMzQ1Ng","authenticationSecret":"MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTM"}';
    }

    public function testConstructor()
    {
        $this->assertSame($this->factory, $this->reader->factory());
        $this->assertSame($this->decoder, $this->reader->decoder());
    }

    public function testConstructorDefaults()
    {
        $this->reader = new KeyReader;

        $this->assertSame(KeyFactory::instance(), $this->reader->factory());
        $this->assertSame(Base64Url::instance(), $this->reader->decoder());
    }

    public function testReadFileFull()
    {
        $stream = fopen('data://text/plain;base64,' . base64_encode($this->jsonDataFull), 'rb');
        Phake::when($this->isolator)->fopen('/path/to/file', 'rb')->thenReturn($stream);
        $key = $this->reader->readFile('/path/to/file');

        $this->assertSame('12345678901234567890123456789012', $key->encryptionSecret());
        $this->assertSame('12345678901234567890123456789013', $key->authenticationSecret());
        $this->assertSame('name', $key->name());
        $this->assertSame('description', $key->description());
        Phake::verify($this->isolator)->fclose($stream);
    }

    public function testReadFileMinimal()
    {
        $stream = fopen('data://text/plain;base64,' . base64_encode($this->jsonDataMinimal), 'rb');
        Phake::when($this->isolator)->fopen('/path/to/file', 'rb')->thenReturn($stream);
        $key = $this->reader->readFile('/path/to/file');

        $this->assertSame('1234567890123456', $key->encryptionSecret());
        $this->assertSame('12345678901234567890123456789013', $key->authenticationSecret());
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

        $this->assertSame('12345678901234567890123456789012', $key->encryptionSecret());
        $this->assertSame('12345678901234567890123456789013', $key->authenticationSecret());
        $this->assertSame('name', $key->name());
        $this->assertSame('description', $key->description());
    }

    public function testReadStreamMinimal()
    {
        $stream = fopen('data://text/plain;base64,' . base64_encode($this->jsonDataMinimal), 'rb');
        $key = $this->reader->readStream($stream);

        $this->assertSame('1234567890123456', $key->encryptionSecret());
        $this->assertSame('12345678901234567890123456789013', $key->authenticationSecret());
        $this->assertNull($key->name());
        $this->assertNull($key->description());
    }

    public function testReadStreamFailureStreamReadWithoutPath()
    {
        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Exception\KeyReadException',
            "Unable to read key."
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

    public function testReadStringFull()
    {
        $key = $this->reader->readString($this->jsonDataFull);

        $this->assertSame('12345678901234567890123456789012', $key->encryptionSecret());
        $this->assertSame('12345678901234567890123456789013', $key->authenticationSecret());
        $this->assertSame('name', $key->name());
        $this->assertSame('description', $key->description());
    }

    public function testReadStringMinimal()
    {
        $key = $this->reader->readString($this->jsonDataMinimal);

        $this->assertSame('1234567890123456', $key->encryptionSecret());
        $this->assertSame('12345678901234567890123456789013', $key->authenticationSecret());
        $this->assertNull($key->name());
        $this->assertNull($key->description());
    }

    public function testReadStringFailureStreamReadWithoutPath()
    {
        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Exception\KeyReadException',
            "Unable to read key."
        );
        $this->reader->readString(null);
    }

    public function testReadStringFailureStreamReadWithPath()
    {
        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Exception\KeyReadException',
            "Unable to read key from '/path/to/file'."
        );
        $this->reader->readString(null, '/path/to/file');
    }

    public function invalidDataData()
    {
        return array(
            'Invalid JSON'                         => array('{'),
            'Missing type'                         => array('{"version":1,"encryptionSecret":"MTIzNDU2Nzg5MDEyMzQ1Ng","authenticationSecret":"MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTM"}'),
            'Invalid type'                         => array('{"type":"lockbox-foo","version":1,"encryptionSecret":"MTIzNDU2Nzg5MDEyMzQ1Ng","authenticationSecret":"MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTM"}'),
            'Missing version'                      => array('{"type":"lockbox-key","encryptionSecret":"MTIzNDU2Nzg5MDEyMzQ1Ng","authenticationSecret":"MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTM"}'),
            'Invalid version'                      => array('{"type":"lockbox-key","version":"1","encryptionSecret":"MTIzNDU2Nzg5MDEyMzQ1Ng","authenticationSecret":"MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTM"}'),
            'Missing encryption secret'            => array('{"type":"lockbox-key","version":1,"authenticationSecret":"MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTM"}'),
            'Invalid base64 encryption secret'     => array('{"type":"lockbox-key","version":1,"encryptionSecret":"MTIzNDU2Nzg5MDEyMzQ1N","authenticationSecret":"MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTM"}'),
            'Invalid encryption secret data'       => array('{"type":"lockbox-key","version":1,"encryptionSecret":"MTIzNDU2","authenticationSecret":"MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTM"}'),
            'Missing authentication secret'        => array('{"type":"lockbox-key","version":1,"encryptionSecret":"MTIzNDU2Nzg5MDEyMzQ1Ng"}'),
            'Invalid base64 authentication secret' => array('{"type":"lockbox-key","version":1,"encryptionSecret":"MTIzNDU2Nzg5MDEyMzQ1Ng","authenticationSecret":"MTIzNDU2Nzg5MDEyMzQ1N"}'),
            'Invalid authentication secret data'   => array('{"type":"lockbox-key","version":1,"encryptionSecret":"MTIzNDU2Nzg5MDEyMzQ1Ng","authenticationSecret":"MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIz"}'),
        );
    }

    /**
     * @dataProvider invalidDataData
     */
    public function testReadStringFailureInvalidDataWithoutPath($data)
    {
        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Exception\KeyReadException',
            "Unable to read key."
        );
        $this->reader->readString($data);
    }

    /**
     * @dataProvider invalidDataData
     */
    public function testReadStringFailureInvalidDataWithPath($data)
    {
        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Exception\KeyReadException',
            "Unable to read key from '/path/to/file'."
        );
        $this->reader->readString($data, '/path/to/file');
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
