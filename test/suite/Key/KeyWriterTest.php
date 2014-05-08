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
use Eloquent\Lockbox\Password\Cipher\PasswordEncryptCipher;
use Eloquent\Lockbox\Password\PasswordEncrypter;
use Eloquent\Lockbox\Transform\PasswordEncryptTransform;
use Icecave\Isolator\Isolator;
use PHPUnit_Framework_TestCase;
use Phake;

class KeyWriterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->transformFactory = Phake::mock(
            'Eloquent\Lockbox\Transform\Factory\PasswordEncryptTransformFactoryInterface'
        );
        $this->encrypter = new PasswordEncrypter($this->transformFactory);
        $this->encoder = new Base64Url;
        $this->isolator = Phake::mock(Isolator::className());
        $this->writer = new KeyWriter($this->encrypter, $this->encoder, $this->isolator);

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

        $this->keyFullStringEncrypted = <<<'EOD'
AQIAAAAKMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEy
MzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDEyMzQ1Njc4OTAxMjM0NTaIkMi2nO33jSCq
d-PyQhN7QlQqvRgk91OJAfQNx8R6msw6mTqLqdQGsoaDNn_ijuCHgSPkcIb1SDDR
7WotmgkNrFB4DmQZwwS0JRkf8bospNcm9YBG_siLrOn1Q_GShPJ67KndCnrUkiuw
A1kQswfNhqYfHE6eYM8oTqHXOEO7d8PQwAhCMXiHWZeev7EMXACQQZiIokZQC1zx
-xBPGy5ulLS1mVpdtce3AmkegN87I5u5CZtLObVbNCJ79YkYASCP6I_rnqJYKGRY
clvzNIzS8-moGPSaS4pGe2L6QeUYSAVcUCSowoVFIRg2zH-eU_OodUMBodRb5HTX
NXFzWE3EDKiJvpb168_dTgCEZRFfYpw-PY16CPRBHABnBlWC_CRE_S0rcWnMsMGh
dMhpnoMo7dMTV-Vc0DhKI9QtMLDhPA

EOD;
        $this->keyMinimalStringEncrypted = <<<'EOD'
AQIAAAAKMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEy
MzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDEyMzQ1Njc4OTAxMjM0NTaahwBMpOBVXCgF
T1Ohh60pZsF7hIP1CBZ2gOYirhC_W_Mf5lZ_JZZHMotEliRZSEgPDe5bZYdOSvLv
T23KWBG-EG1J2AKU_5oEDcsqCDaSFdihYKGF2a3ZawrPGBXaPu6UaVv6e0zSY_uj
6lUqasG17hzwQ8lsqeFbatiui-xuiqbJbdrMPpukzp_H2AqieseWfTcEpNuX4MOm
hNjhk8IF-KcnOnrvPNN6NU9Fchcn21SBi5chj4nvnUg1Icy_hg6QoyCW7pQuA_tP
GV6gLGQkG2udOCa3ncYIw7rRK8xfWZPX-EVN4g

EOD;

        $this->password = 'password';
        $this->iterations = 10;
        $this->salt = '1234567890123456789012345678901234567890123456789012345678901234';
        $this->iv = '1234567890123456';

        $this->randomSource = Phake::mock('Eloquent\Lockbox\Random\RandomSourceInterface');
        $this->keyDeriver = new KeyDeriver(null, $this->randomSource);
        $this->cipher = new PasswordEncryptCipher($this->keyDeriver);
        $this->cipher->initialize($this->password, $this->iterations, $this->salt, $this->iv);
        $this->transform = new PasswordEncryptTransform($this->cipher);

        Phake::when($this->transformFactory)->createTransform($this->password, $this->iterations)
            ->thenReturn($this->transform);
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
        $this->assertSame($this->encrypter, $this->writer->encrypter());
        $this->assertSame($this->encoder, $this->writer->encoder());
    }

    public function testConstructorDefaults()
    {
        $this->writer = new KeyWriter;

        $this->assertSame(PasswordEncrypter::instance(), $this->writer->encrypter());
        $this->assertSame(Base64Url::instance(), $this->writer->encoder());
    }

    public function testWriteFileFull()
    {
        Phake::when($this->isolator)->file_put_contents('/path/to/file', $this->keyFullString)->thenReturn(111);

        $this->assertNull($this->writer->writeFile($this->keyFull, '/path/to/file'));
    }

    public function testWriteFileMinimal()
    {
        Phake::when($this->isolator)->file_put_contents('/path/to/file', $this->keyMinimalString)->thenReturn(111);

        $this->assertNull($this->writer->writeFile($this->keyMinimal, '/path/to/file'));
    }

    public function testWriteFileFailure()
    {
        Phake::when($this->isolator)->file_put_contents('/path/to/file', $this->keyMinimalString)->thenReturn(0);

        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Exception\KeyWriteException',
            "Unable to write key to '/path/to/file'."
        );
        $this->writer->writeFile($this->keyMinimal, '/path/to/file');
    }

    public function testWriteFileWithPasswordFull()
    {
        Phake::when($this->isolator)->file_put_contents('/path/to/file', $this->keyFullStringEncrypted)
            ->thenReturn(111);

        $this->assertNull(
            $this->writer->writeFileWithPassword($this->password, $this->iterations, $this->keyFull, '/path/to/file')
        );
    }

    public function testWriteFileWithPasswordMinimal()
    {
        Phake::when($this->isolator)->file_put_contents('/path/to/file', $this->keyMinimalStringEncrypted)
            ->thenReturn(111);

        $this->assertNull(
            $this->writer->writeFileWithPassword($this->password, $this->iterations, $this->keyMinimal, '/path/to/file')
        );
    }

    public function testWriteFileWithPasswordFailure()
    {
        Phake::when($this->isolator)->file_put_contents('/path/to/file', $this->keyMinimalStringEncrypted)
            ->thenReturn(0);

        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Exception\KeyWriteException',
            "Unable to write key to '/path/to/file'."
        );
        $this->writer->writeFileWithPassword($this->password, $this->iterations, $this->keyMinimal, '/path/to/file');
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

    public function testWriteStreamWithPasswordFull()
    {
        $path = sprintf('%s/%s', sys_get_temp_dir(), uniqid('lockbox-'));
        $this->stream = fopen($path, 'wb');
        $this->writer->writeStreamWithPassword($this->password, $this->iterations, $this->keyFull, $this->stream);

        $this->assertSame($this->keyFullStringEncrypted, file_get_contents($path));
    }

    public function testWriteStreamWithPasswordMinimal()
    {
        $path = sprintf('%s/%s', sys_get_temp_dir(), uniqid('lockbox-'));
        $this->stream = fopen($path, 'wb');
        $this->writer->writeStreamWithPassword($this->password, $this->iterations, $this->keyMinimal, $this->stream);

        $this->assertSame($this->keyMinimalStringEncrypted, file_get_contents($path));
    }

    public function testWriteStreamWithPasswordFailureWithPath()
    {
        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Exception\KeyWriteException',
            "Unable to write key to '/path/to/file'."
        );
        $this->writer
            ->writeStreamWithPassword($this->password, $this->iterations, $this->keyMinimal, null, '/path/to/file');
    }

    public function testWriteStreamWithPasswordFailureWithoutPath()
    {
        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Exception\KeyWriteException',
            "Unable to write key to stream."
        );
        $this->writer->writeStreamWithPassword($this->password, $this->iterations, $this->keyMinimal, null);
    }

    public function testWriteStringFull()
    {
        $this->assertSame($this->keyFullString, $this->writer->writeString($this->keyFull));
    }

    public function testWriteStringMinimal()
    {
        $this->assertSame($this->keyMinimalString, $this->writer->writeString($this->keyMinimal));
    }

    public function testWriteStringWithPasswordFull()
    {
        $this->assertSame(
            $this->keyFullStringEncrypted,
            $this->writer->writeStringWithPassword($this->password, $this->iterations, $this->keyFull)
        );
    }

    public function testWriteStringWithPasswordMinmal()
    {
        $this->assertSame(
            $this->keyMinimalStringEncrypted,
            $this->writer->writeStringWithPassword($this->password, $this->iterations, $this->keyMinimal)
        );
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
