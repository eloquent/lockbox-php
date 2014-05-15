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
use Eloquent\Lockbox\Password\Cipher\Parameters\PasswordEncryptCipherParameters;
use Eloquent\Lockbox\Password\PasswordDecrypter;
use Eloquent\Lockbox\Password\PasswordEncrypter;
use Icecave\Isolator\Isolator;
use PHPUnit_Framework_TestCase;
use Phake;

class KeyReaderTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->factory = new KeyFactory;
        $this->decrypter = new PasswordDecrypter;
        $this->decoder = new Base64Url;
        $this->isolator = Phake::mock(Isolator::className());
        $this->reader = new KeyReader($this->factory, $this->decrypter, $this->decoder, $this->isolator);

        $this->jsonDataFull = <<<EOD
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

        $this->jsonDataFullEncrypted = <<<'EOD'
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
        $this->jsonDataMinimalEncrypted = <<<'EOD'
AQIAAAAKMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEy
MzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDEyMzQ1Njc4OTAxMjM0NTaahwBMpOBVXCgF
T1Ohh60pZsF7hIP1CBZ2gOYirhC_W_Mf5lZ_JZZHMotEliRZSEgPDe5bZYdOSvLv
T23KWBG-EG1J2AKU_5oEDcsqCDaSFdihYKGF2a3ZawrPGBXaPu6UaVv6e0zSY_uj
6lUqasG17hzwQ8lsqeFbatiui-xuiqbJbdrMPpukzp_H2AqieseWfTcEpNuX4MOm
hNjhk8IF-KcnOnrvPNN6NU9Fchcn21SBi5chj4nvnUg1Icy_hg6QoyCW7pQuA_tP
GV6gLGQkG2udOCa3ncYIw7rRK8xfWZPX-EVN4g

EOD;

        $this->password = 'password';
        $this->passwordCallback = function () {
            return 'password';
        };
        $this->iterations = 10;
        $this->parameters = new PasswordEncryptCipherParameters($this->password, $this->iterations);

        $this->encrypter = PasswordEncrypter::instance();
    }

    public function testConstructor()
    {
        $this->assertSame($this->factory, $this->reader->factory());
        $this->assertSame($this->decrypter, $this->reader->decrypter());
        $this->assertSame($this->decoder, $this->reader->decoder());
    }

    public function testConstructorDefaults()
    {
        $this->reader = new KeyReader;

        $this->assertSame(KeyFactory::instance(), $this->reader->factory());
        $this->assertSame(PasswordDecrypter::instance(), $this->reader->decrypter());
        $this->assertSame(Base64Url::instance(), $this->reader->decoder());
    }

    public function testReadFileFull()
    {
        Phake::when($this->isolator)->file_get_contents('/path/to/file')->thenReturn($this->jsonDataFull);
        $key = $this->reader->readFile('/path/to/file');

        $this->assertSame('12345678901234567890123456789012', $key->encryptionSecret());
        $this->assertSame('12345678901234567890123456789013', $key->authenticationSecret());
        $this->assertSame('name', $key->name());
        $this->assertSame('description', $key->description());
    }

    public function testReadFileMinimal()
    {
        Phake::when($this->isolator)->file_get_contents('/path/to/file')->thenReturn($this->jsonDataMinimal);
        $key = $this->reader->readFile('/path/to/file');

        $this->assertSame('1234567890123456', $key->encryptionSecret());
        $this->assertSame('12345678901234567890123456789013', $key->authenticationSecret());
        $this->assertNull($key->name());
        $this->assertNull($key->description());
    }

    public function testReadFileFailureStreamOpen()
    {
        Phake::when($this->isolator)->file_get_contents('/path/to/file')->thenReturn(false);

        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Exception\KeyReadException',
            "Unable to read key from '/path/to/file'."
        );
        $this->reader->readFile('/path/to/file');
    }

    public function testReadFileFailureInvalidKey()
    {
        Phake::when($this->isolator)->file_get_contents('/path/to/file')->thenReturn('{');
        $e = null;
        try {
            $this->reader->readFile('/path/to/file');
        } catch (Exception\KeyReadException $e) {
        }

        $this->assertInstanceOf('Eloquent\Lockbox\Key\Exception\KeyReadException', $e);
        $this->assertSame("Unable to read key from '/path/to/file'.", $e->getMessage());
    }

    public function testReadFileWithPasswordFull()
    {
        Phake::when($this->isolator)->file_get_contents('/path/to/file')->thenReturn($this->jsonDataFullEncrypted);
        $key = $this->reader->readFileWithPassword($this->password, '/path/to/file');

        $this->assertSame('12345678901234567890123456789012', $key->encryptionSecret());
        $this->assertSame('12345678901234567890123456789013', $key->authenticationSecret());
        $this->assertSame('name', $key->name());
        $this->assertSame('description', $key->description());
    }

    public function testReadFileWithPasswordMinimal()
    {
        Phake::when($this->isolator)->file_get_contents('/path/to/file')->thenReturn($this->jsonDataMinimalEncrypted);
        $key = $this->reader->readFileWithPassword($this->password, '/path/to/file');

        $this->assertSame('1234567890123456', $key->encryptionSecret());
        $this->assertSame('12345678901234567890123456789013', $key->authenticationSecret());
        $this->assertNull($key->name());
        $this->assertNull($key->description());
    }

    public function testReadFileWithPasswordFailureStreamOpen()
    {
        Phake::when($this->isolator)->file_get_contents('/path/to/file')->thenReturn(false);

        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Exception\KeyReadException',
            "Unable to read key from '/path/to/file'."
        );
        $this->reader->readFileWithPassword($this->password, '/path/to/file');
    }

    public function testReadFileWithPasswordFailureInvalidKey()
    {
        Phake::when($this->isolator)->file_get_contents('/path/to/file')->thenReturn('{');
        $e = null;
        try {
            $this->reader->readFileWithPassword($this->password, '/path/to/file');
        } catch (Exception\KeyReadException $e) {
        }

        $this->assertInstanceOf('Eloquent\Lockbox\Key\Exception\KeyReadException', $e);
        $this->assertSame("Unable to read key from '/path/to/file'.", $e->getMessage());
    }

    public function testReadFileWithPasswordCallbackFull()
    {
        Phake::when($this->isolator)->file_get_contents('/path/to/file')->thenReturn($this->jsonDataFull);
        $key = $this->reader->readFileWithPasswordCallback($this->passwordCallback, '/path/to/file');

        $this->assertSame('12345678901234567890123456789012', $key->encryptionSecret());
        $this->assertSame('12345678901234567890123456789013', $key->authenticationSecret());
        $this->assertSame('name', $key->name());
        $this->assertSame('description', $key->description());
    }

    public function testReadFileWithPasswordCallbackMinimal()
    {
        Phake::when($this->isolator)->file_get_contents('/path/to/file')->thenReturn($this->jsonDataMinimal);
        $key = $this->reader->readFileWithPasswordCallback($this->passwordCallback, '/path/to/file');

        $this->assertSame('1234567890123456', $key->encryptionSecret());
        $this->assertSame('12345678901234567890123456789013', $key->authenticationSecret());
        $this->assertNull($key->name());
        $this->assertNull($key->description());
    }

    public function testReadFileWithPasswordCallbackFullEncrypted()
    {
        Phake::when($this->isolator)->file_get_contents('/path/to/file')->thenReturn($this->jsonDataFullEncrypted);
        $key = $this->reader->readFileWithPasswordCallback($this->passwordCallback, '/path/to/file');

        $this->assertSame('12345678901234567890123456789012', $key->encryptionSecret());
        $this->assertSame('12345678901234567890123456789013', $key->authenticationSecret());
        $this->assertSame('name', $key->name());
        $this->assertSame('description', $key->description());
    }

    public function testReadFileWithPasswordCallbackMinimalEncrypted()
    {
        Phake::when($this->isolator)->file_get_contents('/path/to/file')->thenReturn($this->jsonDataMinimalEncrypted);
        $key = $this->reader->readFileWithPasswordCallback($this->passwordCallback, '/path/to/file');

        $this->assertSame('1234567890123456', $key->encryptionSecret());
        $this->assertSame('12345678901234567890123456789013', $key->authenticationSecret());
        $this->assertNull($key->name());
        $this->assertNull($key->description());
    }

    public function testReadFileWithPasswordCallbackFailureStreamOpen()
    {
        Phake::when($this->isolator)->file_get_contents('/path/to/file')->thenReturn(false);

        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Exception\KeyReadException',
            "Unable to read key from '/path/to/file'."
        );
        $this->reader->readFileWithPasswordCallback($this->passwordCallback, '/path/to/file');
    }

    public function testReadFileWithPasswordCallbackFailureInvalidKey()
    {
        Phake::when($this->isolator)->file_get_contents('/path/to/file')->thenReturn('{');
        $e = null;
        try {
            $this->reader->readFileWithPasswordCallback($this->passwordCallback, '/path/to/file');
        } catch (Exception\KeyReadException $e) {
        }

        $this->assertInstanceOf('Eloquent\Lockbox\Key\Exception\KeyReadException', $e);
        $this->assertSame("Unable to read key from '/path/to/file'.", $e->getMessage());
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

    public function testReadStreamWithPasswordFull()
    {
        $stream = fopen('data://text/plain;base64,' . base64_encode($this->jsonDataFullEncrypted), 'rb');
        $key = $this->reader->readStreamWithPassword($this->password, $stream);

        $this->assertSame('12345678901234567890123456789012', $key->encryptionSecret());
        $this->assertSame('12345678901234567890123456789013', $key->authenticationSecret());
        $this->assertSame('name', $key->name());
        $this->assertSame('description', $key->description());
    }

    public function testReadStreamWithPasswordMinimal()
    {
        $stream = fopen('data://text/plain;base64,' . base64_encode($this->jsonDataMinimalEncrypted), 'rb');
        $key = $this->reader->readStreamWithPassword($this->password, $stream);

        $this->assertSame('1234567890123456', $key->encryptionSecret());
        $this->assertSame('12345678901234567890123456789013', $key->authenticationSecret());
        $this->assertNull($key->name());
        $this->assertNull($key->description());
    }

    public function testReadStreamWithPasswordFailureStreamReadWithoutPath()
    {
        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Exception\KeyReadException',
            "Unable to read key."
        );
        $this->reader->readStreamWithPassword($this->password, null);
    }

    public function testReadStreamWithPasswordFailureStreamReadWithPath()
    {
        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Exception\KeyReadException',
            "Unable to read key from '/path/to/file'."
        );
        $this->reader->readStreamWithPassword($this->password, null, '/path/to/file');
    }

    public function testReadStreamWithPasswordCallbackFull()
    {
        $stream = fopen('data://text/plain;base64,' . base64_encode($this->jsonDataFull), 'rb');
        $key = $this->reader->readStreamWithPasswordCallback($this->passwordCallback, $stream);

        $this->assertSame('12345678901234567890123456789012', $key->encryptionSecret());
        $this->assertSame('12345678901234567890123456789013', $key->authenticationSecret());
        $this->assertSame('name', $key->name());
        $this->assertSame('description', $key->description());
    }

    public function testReadStreamWithPasswordCallbackMinimal()
    {
        $stream = fopen('data://text/plain;base64,' . base64_encode($this->jsonDataMinimal), 'rb');
        $key = $this->reader->readStreamWithPasswordCallback($this->passwordCallback, $stream);

        $this->assertSame('1234567890123456', $key->encryptionSecret());
        $this->assertSame('12345678901234567890123456789013', $key->authenticationSecret());
        $this->assertNull($key->name());
        $this->assertNull($key->description());
    }

    public function testReadStreamWithPasswordCallbackFullEncrypted()
    {
        $stream = fopen('data://text/plain;base64,' . base64_encode($this->jsonDataFullEncrypted), 'rb');
        $key = $this->reader->readStreamWithPasswordCallback($this->passwordCallback, $stream);

        $this->assertSame('12345678901234567890123456789012', $key->encryptionSecret());
        $this->assertSame('12345678901234567890123456789013', $key->authenticationSecret());
        $this->assertSame('name', $key->name());
        $this->assertSame('description', $key->description());
    }

    public function testReadStreamWithPasswordCallbackMinimalEncrypted()
    {
        $stream = fopen('data://text/plain;base64,' . base64_encode($this->jsonDataMinimalEncrypted), 'rb');
        $key = $this->reader->readStreamWithPasswordCallback($this->passwordCallback, $stream);

        $this->assertSame('1234567890123456', $key->encryptionSecret());
        $this->assertSame('12345678901234567890123456789013', $key->authenticationSecret());
        $this->assertNull($key->name());
        $this->assertNull($key->description());
    }

    public function testReadStreamWithPasswordCallbackFailureStreamReadWithoutPath()
    {
        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Exception\KeyReadException',
            "Unable to read key."
        );
        $this->reader->readStreamWithPasswordCallback($this->passwordCallback, null);
    }

    public function testReadStreamWithPasswordCallbackFailureStreamReadWithPath()
    {
        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Exception\KeyReadException',
            "Unable to read key from '/path/to/file'."
        );
        $this->reader->readStreamWithPasswordCallback($this->passwordCallback, null, '/path/to/file');
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

    public function testReadStringWithPasswordFull()
    {
        $key = $this->reader->readStringWithPassword($this->password, $this->jsonDataFullEncrypted);

        $this->assertSame('12345678901234567890123456789012', $key->encryptionSecret());
        $this->assertSame('12345678901234567890123456789013', $key->authenticationSecret());
        $this->assertSame('name', $key->name());
        $this->assertSame('description', $key->description());
    }

    public function testReadStringWithPasswordMinimal()
    {
        $key = $this->reader->readStringWithPassword($this->password, $this->jsonDataMinimalEncrypted);

        $this->assertSame('1234567890123456', $key->encryptionSecret());
        $this->assertSame('12345678901234567890123456789013', $key->authenticationSecret());
        $this->assertNull($key->name());
        $this->assertNull($key->description());
    }

    public function testReadStringWithPasswordFailureNotEncrypted()
    {
        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Exception\KeyReadException',
            "Unable to read key."
        );
        $this->reader->readStringWithPassword($this->password, $this->jsonDataMinimal);
    }

    public function testReadStringWithPasswordFailureNotEncryptedWithPath()
    {
        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Exception\KeyReadException',
            "Unable to read key from '/path/to/file'."
        );
        $this->reader->readStringWithPassword($this->password, $this->jsonDataMinimal, '/path/to/file');
    }

    public function testReadStringWithPasswordFailureBadKey()
    {
        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Exception\KeyReadException',
            "Unable to read key."
        );
        $this->reader->readStringWithPassword($this->password, $this->encrypter->encrypt($this->parameters, '{}'));
    }

    public function testReadStringWithPasswordCallbackFull()
    {
        $key = $this->reader->readStringWithPasswordCallback($this->passwordCallback, $this->jsonDataFull);

        $this->assertSame('12345678901234567890123456789012', $key->encryptionSecret());
        $this->assertSame('12345678901234567890123456789013', $key->authenticationSecret());
        $this->assertSame('name', $key->name());
        $this->assertSame('description', $key->description());
    }

    public function testReadStringWithPasswordCallbackMinimal()
    {
        $key = $this->reader->readStringWithPasswordCallback($this->passwordCallback, $this->jsonDataMinimal);

        $this->assertSame('1234567890123456', $key->encryptionSecret());
        $this->assertSame('12345678901234567890123456789013', $key->authenticationSecret());
        $this->assertNull($key->name());
        $this->assertNull($key->description());
    }

    public function testReadStringWithPasswordCallbackFullEncrypted()
    {
        $key = $this->reader->readStringWithPasswordCallback($this->passwordCallback, $this->jsonDataFullEncrypted);

        $this->assertSame('12345678901234567890123456789012', $key->encryptionSecret());
        $this->assertSame('12345678901234567890123456789013', $key->authenticationSecret());
        $this->assertSame('name', $key->name());
        $this->assertSame('description', $key->description());
    }

    public function testReadStringWithPasswordCallbackMinimalEncrypted()
    {
        $key = $this->reader->readStringWithPasswordCallback($this->passwordCallback, $this->jsonDataMinimalEncrypted);

        $this->assertSame('1234567890123456', $key->encryptionSecret());
        $this->assertSame('12345678901234567890123456789013', $key->authenticationSecret());
        $this->assertNull($key->name());
        $this->assertNull($key->description());
    }

    public function testReadStringWithPasswordCallbackFailureBadKey()
    {
        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Exception\KeyReadException',
            "Unable to read key."
        );
        $this->reader->readStringWithPasswordCallback(
            $this->passwordCallback,
            $this->encrypter->encrypt($this->parameters, '{}')
        );
    }

    public function testReadStringWithPasswordCallbackFailureBadKeyWithPath()
    {
        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Exception\KeyReadException',
            "Unable to read key from '/path/to/file'."
        );
        $this->reader->readStringWithPasswordCallback(
            $this->passwordCallback,
            $this->encrypter->encrypt($this->parameters, '{}'),
            '/path/to/file'
        );
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
