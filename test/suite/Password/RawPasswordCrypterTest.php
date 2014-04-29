<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Password;

use Eloquent\Liberator\Liberator;
use Eloquent\Lockbox\Key\KeyDeriver;
use Eloquent\Lockbox\Transform\Factory\PasswordEncryptTransformFactory;
use PHPUnit_Framework_TestCase;
use Phake;

/**
 * @covers \Eloquent\Lockbox\Password\RawPasswordCrypter
 * @covers \Eloquent\Lockbox\Password\AbstractPasswordCrypter
 * @covers \Eloquent\Lockbox\Password\RawPasswordEncrypter
 * @covers \Eloquent\Lockbox\Password\RawPasswordDecrypter
 */
class RawPasswordCrypterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->randomSource = Phake::mock('Eloquent\Lockbox\Random\RandomSourceInterface');
        $this->keyDeriver = new KeyDeriver(null, $this->randomSource);
        $this->encrypter = new RawPasswordEncrypter(new PasswordEncryptTransformFactory($this->keyDeriver));
        $this->decryptTransformFactory = Phake::partialMock(
            'Eloquent\Lockbox\Transform\Factory\PasswordDecryptTransformFactoryInterface'
        );
        $this->decrypter = new RawPasswordDecrypter($this->decryptTransformFactory);
        $this->crypter = new RawPasswordCrypter($this->encrypter, $this->decrypter);

        $this->password = 'foobar';
        $this->decryptTransform = Phake::partialMock(
            'Eloquent\Lockbox\Transform\PasswordDecryptTransform',
            $this->password,
            $this->keyDeriver
        );

        Phake::when($this->decryptTransformFactory)->createTransform($this->password)
            ->thenReturn($this->decryptTransform);

        $this->version = chr(1);
        $this->type = chr(2);
        $this->iterations = 10;
        $this->iterationsData = pack('N', $this->iterations);
        $this->salt = '1234567890123456789012345678901234567890123456789012345678901234';
        $this->iv = '1234567890123456';

        Phake::when($this->randomSource)->generate(64)->thenReturn($this->salt);
        Phake::when($this->randomSource)->generate(16)->thenReturn($this->iv);

        list($this->key) = $this->keyDeriver->deriveKeyFromPassword($this->password, $this->iterations);
    }

    public function testConstructor()
    {
        $this->assertSame($this->encrypter, $this->crypter->encrypter());
        $this->assertSame($this->decrypter, $this->crypter->decrypter());
    }

    public function testConstructorDefaults()
    {
        $this->crypter = new RawPasswordCrypter;

        $this->assertSame(RawPasswordEncrypter::instance(), $this->crypter->encrypter());
        $this->assertSame(RawPasswordDecrypter::instance(), $this->crypter->decrypter());
    }

    public function encryptionData()
    {
        $data = array();
        foreach (array(0, 1, 1024) as $dataSize) {
            $data[sprintf('%d byte(s)', $dataSize)] = array($dataSize);
        }

        return $data;
    }

    /**
     * @dataProvider encryptionData
     */
    public function testEncryptDecrypt($dataSize)
    {
        $this->decrypter = new RawPasswordDecrypter;
        $this->crypter = new RawPasswordCrypter($this->encrypter, $this->decrypter);
        $data = str_repeat('A', $dataSize);
        $encrypted = $this->crypter->encrypt($this->password, $this->iterations, $data);
        $result = $this->crypter->decrypt($this->password, $encrypted);

        $this->assertTrue($result->isSuccessful());
        $this->assertSame($data, $result->data());
        $this->assertSame($this->iterations, $result->iterations());
    }

    /**
     * @dataProvider encryptionData
     */
    public function testEncryptDecryptStreaming($dataSize)
    {
        $this->decrypter = new RawPasswordDecrypter;
        $this->crypter = new RawPasswordCrypter($this->encrypter, $this->decrypter);
        $encryptStream = $this->crypter->createEncryptStream($this->password, $this->iterations);
        $decryptStream = $this->crypter->createDecryptStream($this->password);
        $encryptStream->pipe($decryptStream);
        $decrypted = '';
        $decryptStream->on(
            'data',
            function ($data, $stream) use (&$decrypted) {
                $decrypted .= $data;
            }
        );
        $data = '';
        for ($i = 0; $i < $dataSize; $i ++) {
            $data .= 'A';
            $encryptStream->write('A');
        }
        $encryptStream->end();

        $this->assertSame($data, $decrypted);
    }

    public function testDecryptFailureEmptyVersion()
    {
        $data = '';
        $data .= $this->authenticate($data);
        $result = $this->crypter->decrypt($this->key, $data);

        $this->assertFalse($result->isSuccessful());
        $this->assertSame('INVALID_SIZE', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertNull($result->iterations());
        Phake::verify($this->decryptTransform, Phake::never())->transform(Phake::anyParameters());
    }

    public function testDecryptFailureUnsupportedVersion()
    {
        $header = chr(111) . str_pad('', 85, '1234567890');
        $block = str_pad('', 16, '1234567890');
        $data = $header . $block . $this->authenticate($block, 2) . $this->authenticate($header . $block);
        $result = $this->crypter->decrypt($this->password, $data);

        $this->assertFalse($result->isSuccessful());
        $this->assertSame('UNSUPPORTED_VERSION', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertNull($result->iterations());
    }

    public function testDecryptFailureEmptyType()
    {
        $data = $this->version;
        $data .= $this->authenticate($data);
        $result = $this->crypter->decrypt($this->password, $data);

        $this->assertFalse($result->isSuccessful());
        $this->assertSame('INVALID_SIZE', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertNull($result->iterations());
        Phake::verify($this->decryptTransform, Phake::never())->transform(Phake::anyParameters());
    }

    public function testDecryptUnsupportedType()
    {
        $header = $this->version . chr(111) . str_pad('', 84, '1234567890');
        $block = str_pad('', 16, '1234567890');
        $data = $header . $block . $this->authenticate($block, 2) . $this->authenticate($header . $block);
        $result = $this->crypter->decrypt($this->password, $data);

        $this->assertFalse($result->isSuccessful());
        $this->assertSame('UNSUPPORTED_TYPE', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertNull($result->iterations());
    }

    public function testDecryptFailureEmptyIterations()
    {
        $data = $this->version . $this->type;
        $data .= $this->authenticate($data);
        $result = $this->crypter->decrypt($this->password, $data);

        $this->assertFalse($result->isSuccessful());
        $this->assertSame('INVALID_SIZE', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertNull($result->iterations());
        Phake::verify($this->decryptTransform, Phake::never())->transform(Phake::anyParameters());
    }

    public function testDecryptFailureEmptySalt()
    {
        $data = $this->version . $this->type . $this->iterationsData;
        $data .= $this->authenticate($data);
        $result = $this->crypter->decrypt($this->password, $data);

        $this->assertFalse($result->isSuccessful());
        $this->assertSame('INVALID_SIZE', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertNull($result->iterations());
        Phake::verify($this->decryptTransform, Phake::never())->transform(Phake::anyParameters());
    }

    public function testDecryptFailureEmptyIv()
    {
        $data = $this->version . $this->type . $this->iterationsData . $this->salt;
        $data .= $this->authenticate($data);
        $result = $this->crypter->decrypt($this->password, $data);

        $this->assertFalse($result->isSuccessful());
        $this->assertSame('INVALID_SIZE', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertNull($result->iterations());
        Phake::verify($this->decryptTransform, Phake::never())->transform(Phake::anyParameters());
    }

    public function testDecryptFailureShortMac()
    {
        $data = $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv .
            '789012345678901234567890123';
        $result = $this->crypter->decrypt($this->password, $data);

        $this->assertFalse($result->isSuccessful());
        $this->assertSame('INVALID_SIZE', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertNull($result->iterations());
        Phake::verify($this->decryptTransform, Phake::never())->transform(Phake::anyParameters());
    }

    public function testDecryptFailureEmptyCiphertext()
    {
        $data = $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv;
        $data .= $this->authenticate($data);
        $result = $this->crypter->decrypt($this->password, $data);

        $this->assertFalse($result->isSuccessful());
        $this->assertSame('INVALID_SIZE', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertNull($result->iterations());
        Phake::verify($this->decryptTransform, Phake::never())->transform(Phake::anyParameters());
    }

    public function testDecryptFailureBadBlockMac()
    {
        $header = $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv;
        $block = 'foobarbazquxdoom';
        $data = $header . $block . '12' . $this->authenticate($header . $block);
        $result = $this->crypter->decrypt($this->password, $data);

        $this->assertFalse($result->isSuccessful());
        $this->assertSame('INVALID_MAC', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertNull($result->iterations());
        Phake::verify($this->decryptTransform, Phake::never())->transform(Phake::anyParameters());
    }

    public function testDecryptFailureBadMac()
    {
        $header = $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv;
        $block = 'foobarbazquxdoom';
        $data = $header . $block . $this->authenticate($block, 2) . '12345678901234567890123456789012';
        $result = $this->crypter->decrypt($this->password, $data);

        $this->assertFalse($result->isSuccessful());
        $this->assertSame('INVALID_MAC', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertNull($result->iterations());
        Phake::verify($this->decryptTransform, Phake::never())->transform(Phake::anyParameters());
    }

    public function testDecryptFailureBadAesData()
    {
        $header = $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv;
        $block = 'foobarbazquxdoom';
        $data = $header . $block . $this->authenticate($block, 2) . $this->authenticate($header . $block);
        $result = $this->crypter->decrypt($this->password, $data);

        $this->assertFalse($result->isSuccessful());
        $this->assertSame('INVALID_PADDING', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertNull($result->iterations());
    }

    public function testDecryptFailureBadPadding()
    {
        $header = $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv;
        $block = mcrypt_encrypt(
            MCRYPT_RIJNDAEL_128,
            $this->key->encryptionSecret(),
            'foobar',
            MCRYPT_MODE_CBC,
            $this->iv
        );
        $data = $header . $block . $this->authenticate($block, 2) . $this->authenticate($header . $block);
        $result = $this->crypter->decrypt($this->password, $data);

        $this->assertFalse($result->isSuccessful());
        $this->assertSame('INVALID_PADDING', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertNull($result->iterations());
    }

    public function testInstance()
    {
        $className = get_class($this->crypter);
        Liberator::liberateClass($className)->instance = null;
        $instance = $className::instance();

        $this->assertInstanceOf($className, $instance);
        $this->assertSame($instance, $className::instance());
    }

    protected function pad($data)
    {
        $padSize = intval(16 - (strlen($data) % 16));

        return $data . str_repeat(chr($padSize), $padSize);
    }

    protected function authenticate($data, $size = null)
    {
        $mac = hash_hmac(
            'sha256',
            $data,
            $this->key->authenticationSecret(),
            true
        );

        if (null !== $size) {
            $mac = substr($mac, 0, $size);
        }

        return $mac;
    }
}