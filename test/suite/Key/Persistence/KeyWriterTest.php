<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Key\Persistence;

use Eloquent\Endec\Base64\Base64Url;
use Eloquent\Liberator\Liberator;
use Eloquent\Lockbox\Key\Deriver\KeyDeriver;
use Eloquent\Lockbox\Key\Key;
use Eloquent\Lockbox\Password\Cipher\Factory\PasswordEncryptCipherFactory;
use Eloquent\Lockbox\Password\Cipher\Parameters\PasswordEncryptParameters;
use Eloquent\Lockbox\Password\Password;
use Eloquent\Lockbox\Password\PasswordEncrypter;
use Eloquent\Lockbox\Password\RawPasswordEncrypter;
use Icecave\Isolator\Isolator;
use PHPUnit_Framework_TestCase;
use Phake;

class KeyWriterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->randomSource = Phake::mock('Eloquent\Lockbox\Random\RandomSourceInterface');
        $this->keyDeriver = new KeyDeriver($this->randomSource);
        $this->cipherFactory = new PasswordEncryptCipherFactory($this->randomSource, $this->keyDeriver);
        $this->encrypter = new PasswordEncrypter(new RawPasswordEncrypter($this->cipherFactory));
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
    "encryptSecret": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI",
    "authSecret": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTM"
}

EOD;
        $this->keyMinimalString = <<<'EOD'
{
    "type": "lockbox-key",
    "version": 1,
    "encryptSecret": "MTIzNDU2Nzg5MDEyMzQ1Ng",
    "authSecret": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTM"
}

EOD;

        $this->keyFullStringEncrypted = <<<'EOD'
AQIAAAAKMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEy
MzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDEyMzQ1Njc4OTAxMjM0NTaIkMi2nO33jSCq
d-PyQhN7QlQqvRgk91OJAfQNx8R6msw6mTqLqdQGsoaDNn_ijuCHgSPkcIb1SDDR
7WotmgkNrFB4DmQZwwS0JRkf8bospNcm9YBG_siLrOn1Q_GShPJ67KndCnrUkiuw
A1kQswfNhqYfHE6eYM8oTqHXOEMNtkD0aS9Spna3cJo2pePxLN1cuBnBteHcMPcn
KS2cAEdHxqhh5uZjfsOCPe72R64YiG8tHcalAIl65Dab62GIZNT-Z7FtvEVPw3Yu
VGyfbV7pq-OnU89gHnzRz4pgtcNmCD4Otss0TZAnSbqwgmC5qUPucJdZetGOnLRG
KRxgNRgnoMOHTJgxa1saY9SNjTmsuIyqiKXEPIu5lnbaRlcZc-5VEKZ52UJBULU-
d4Fk9A

EOD;
        $this->keyMinimalStringEncrypted = <<<'EOD'
AQIAAAAKMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEy
MzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDEyMzQ1Njc4OTAxMjM0NTaahwBMpOBVXCgF
T1Ohh60pZsF7hIP1CBZ2gOYirhC_W_Mf5lZ_JZZHMotEliRZSEgPDe5bZYe2X7u9
jwgK_tb_M7DUHrM9JZovYT_idOCFhG0TezW-9akE93KjXw912cicnUSXZsbJPjRP
CbwPOREHWrexLCX7v_mJAFve6JOr5plnKyWmlxXdCxXMmXrUTLro9jLCfdV_wTwd
S6Xp75O49bApB6QDfogtFS37eHGKSLLGQOMRxeRD5vCiNeyFzXD-wBamjsAGM-Kq
zOopKXDBccm2MsrrnRLvqQYgLYldVpAsAwA9zQ

EOD;

        $this->password = new Password('password');
        $this->iterations = 10;
        $this->parameters = new PasswordEncryptParameters($this->password, $this->iterations);
        $this->salt = '1234567890123456789012345678901234567890123456789012345678901234';
        $this->iv = '1234567890123456';

        Phake::when($this->randomSource)->generate(64)->thenReturn($this->salt);
        Phake::when($this->randomSource)->generate(16)->thenReturn($this->iv);
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
            'Eloquent\Lockbox\Key\Persistence\Exception\KeyWriteException',
            "Unable to write key to '/path/to/file'."
        );
        $this->writer->writeFile($this->keyMinimal, '/path/to/file');
    }

    public function testWriteFileWithPasswordFull()
    {
        Phake::when($this->isolator)->file_put_contents('/path/to/file', $this->keyFullStringEncrypted)
            ->thenReturn(111);

        $this->assertNull($this->writer->writeFileWithPassword($this->keyFull, $this->parameters, '/path/to/file'));
    }

    public function testWriteFileWithPasswordMinimal()
    {
        Phake::when($this->isolator)->file_put_contents('/path/to/file', $this->keyMinimalStringEncrypted)
            ->thenReturn(111);

        $this->assertNull($this->writer->writeFileWithPassword($this->keyMinimal, $this->parameters, '/path/to/file'));
    }

    public function testWriteFileWithPasswordFailure()
    {
        Phake::when($this->isolator)->file_put_contents('/path/to/file', $this->keyMinimalStringEncrypted)
            ->thenReturn(0);

        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Persistence\Exception\KeyWriteException',
            "Unable to write key to '/path/to/file'."
        );
        $this->writer->writeFileWithPassword($this->keyMinimal, $this->parameters, '/path/to/file');
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
            'Eloquent\Lockbox\Key\Persistence\Exception\KeyWriteException',
            "Unable to write key to '/path/to/file'."
        );
        $this->writer->writeStream($this->keyMinimal, null, '/path/to/file');
    }

    public function testWriteStreamFailureWithoutPath()
    {
        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Persistence\Exception\KeyWriteException',
            "Unable to write key to stream."
        );
        $this->writer->writeStream($this->keyMinimal, null);
    }

    public function testWriteStreamWithPasswordFull()
    {
        $path = sprintf('%s/%s', sys_get_temp_dir(), uniqid('lockbox-'));
        $this->stream = fopen($path, 'wb');
        $this->writer->writeStreamWithPassword($this->keyFull, $this->parameters, $this->stream);

        $this->assertSame($this->keyFullStringEncrypted, file_get_contents($path));
    }

    public function testWriteStreamWithPasswordMinimal()
    {
        $path = sprintf('%s/%s', sys_get_temp_dir(), uniqid('lockbox-'));
        $this->stream = fopen($path, 'wb');
        $this->writer->writeStreamWithPassword($this->keyMinimal, $this->parameters, $this->stream);

        $this->assertSame($this->keyMinimalStringEncrypted, file_get_contents($path));
    }

    public function testWriteStreamWithPasswordFailureWithPath()
    {
        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Persistence\Exception\KeyWriteException',
            "Unable to write key to '/path/to/file'."
        );
        $this->writer->writeStreamWithPassword($this->keyMinimal, $this->parameters, null, '/path/to/file');
    }

    public function testWriteStreamWithPasswordFailureWithoutPath()
    {
        $this->setExpectedException(
            'Eloquent\Lockbox\Key\Persistence\Exception\KeyWriteException',
            "Unable to write key to stream."
        );
        $this->writer->writeStreamWithPassword($this->keyMinimal, $this->parameters, null);
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
            $this->writer->writeStringWithPassword($this->keyFull, $this->parameters)
        );
    }

    public function testWriteStringWithPasswordMinmal()
    {
        $this->assertSame(
            $this->keyMinimalStringEncrypted,
            $this->writer->writeStringWithPassword($this->keyMinimal, $this->parameters)
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
