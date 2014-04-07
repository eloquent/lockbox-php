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
 * @covers \Eloquent\Lockbox\Password\RawPasswordCipher
 * @covers \Eloquent\Lockbox\Password\AbstractPasswordCipher
 * @covers \Eloquent\Lockbox\Password\RawPasswordEncrypter
 * @covers \Eloquent\Lockbox\Password\RawPasswordDecrypter
 */
class RawPasswordCipherTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->randomSource = Phake::mock('Eloquent\Lockbox\Random\RandomSourceInterface');
        $this->keyDeriver = new KeyDeriver(null, $this->randomSource);
        $this->encrypter = new RawPasswordEncrypter(new PasswordEncryptTransformFactory($this->keyDeriver));
        $this->decrypter = new RawPasswordDecrypter;
        $this->cipher = new RawPasswordCipher($this->encrypter, $this->decrypter);

        $this->version = chr(1);
        $this->type = chr(2);
        $this->password = 'foobar';
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
        $this->assertSame($this->encrypter, $this->cipher->encrypter());
        $this->assertSame($this->decrypter, $this->cipher->decrypter());
    }

    public function testConstructorDefaults()
    {
        $this->cipher = new RawPasswordCipher;

        $this->assertSame(RawPasswordEncrypter::instance(), $this->cipher->encrypter());
        $this->assertSame(RawPasswordDecrypter::instance(), $this->cipher->decrypter());
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
        $data = str_repeat('A', $dataSize);
        $encrypted = $this->cipher->encrypt($this->password, $this->iterations, $data);
        $decryptionResult = $this->cipher->decrypt($this->password, $encrypted);

        $this->assertTrue($decryptionResult->isSuccessful());
        $this->assertSame($data, $decryptionResult->data());
        $this->assertSame($this->iterations, $decryptionResult->iterations());
    }

    /**
     * @dataProvider encryptionData
     */
    public function testEncryptDecryptStreaming($dataSize)
    {
        $encryptStream = $this->cipher->createEncryptStream($this->password, $this->iterations);
        $decryptStream = $this->cipher->createDecryptStream($this->password);
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
        $data .= $this->authenticationCode($data);
        $result = $this->cipher->decrypt($this->password, $data);

        $this->assertFalse($result->isSuccessful());
        $this->assertSame('INSUFFICIENT_DATA', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertNull($result->iterations());
    }

    public function testDecryptFailureUnsupportedVersion()
    {
        $data = ord(111) . str_pad('', 200, '1234567890');
        $data .= $this->authenticationCode($data);
        $result = $this->cipher->decrypt($this->password, $data);

        $this->assertFalse($result->isSuccessful());
        $this->assertSame('UNSUPPORTED_VERSION', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertNull($result->iterations());
    }

    public function testDecryptFailureEmptyType()
    {
        $data = $this->version;
        $data .= $this->authenticationCode($data);
        $result = $this->cipher->decrypt($this->password, $data);

        $this->assertFalse($result->isSuccessful());
        $this->assertSame('INSUFFICIENT_DATA', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertNull($result->iterations());
    }

    public function testDecryptUnsupportedType()
    {
        $data = $this->version . ord(111) . str_pad('', 200, '1234567890');
        $data .= $this->authenticationCode($data);
        $result = $this->cipher->decrypt($this->password, $data);

        $this->assertFalse($result->isSuccessful());
        $this->assertSame('UNSUPPORTED_TYPE', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertNull($result->iterations());
    }

    public function testDecryptFailureEmptyIterations()
    {
        $data = $this->version . $this->type;
        $data .= $this->authenticationCode($data);
        $result = $this->cipher->decrypt($this->password, $data);

        $this->assertFalse($result->isSuccessful());
        $this->assertSame('INSUFFICIENT_DATA', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertNull($result->iterations());
    }

    public function testDecryptFailureEmptySalt()
    {
        $data = $this->version . $this->type . $this->iterationsData;
        $data .= $this->authenticationCode($data);
        $result = $this->cipher->decrypt($this->password, $data);

        $this->assertFalse($result->isSuccessful());
        $this->assertSame('INSUFFICIENT_DATA', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertNull($result->iterations());
    }

    public function testDecryptFailureEmptyIv()
    {
        $data = $this->version . $this->type . $this->iterationsData . $this->salt;
        $data .= $this->authenticationCode($data);
        $result = $this->cipher->decrypt($this->password, $data);

        $this->assertFalse($result->isSuccessful());
        $this->assertSame('INSUFFICIENT_DATA', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertNull($result->iterations());
    }

    public function testDecryptFailureShortMac()
    {
        $data = $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv .
            '789012345678901234567890123';
        $result = $this->cipher->decrypt($this->password, $data);

        $this->assertFalse($result->isSuccessful());
        $this->assertSame('INSUFFICIENT_DATA', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertNull($result->iterations());
    }

    public function testDecryptFailureEmptyCiphertext()
    {
        $data = $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv;
        $data .= $this->authenticationCode($data);
        $result = $this->cipher->decrypt($this->password, $data);

        $this->assertFalse($result->isSuccessful());
        $this->assertSame('INVALID_PADDING', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertNull($result->iterations());
    }

    public function testDecryptFailureBadMac()
    {
        $decryptTransformFactory = Phake::partialMock(
            'Eloquent\Lockbox\Transform\Factory\PasswordDecryptTransformFactoryInterface'
        );
        $decryptTransform = Phake::partialMock(
            'Eloquent\Lockbox\Transform\PasswordDecryptTransform',
            $this->password,
            $this->keyDeriver
        );
        $this->decrypter = new RawPasswordDecrypter($decryptTransformFactory);
        $this->cipher = new RawPasswordCipher($this->encrypter, $this->decrypter);
        Phake::when($decryptTransformFactory)->createTransform($this->password)->thenReturn($decryptTransform);
        $data = $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv .
            'foobar1234567890123456789012345678';
        $result = $this->cipher->decrypt($this->password, $data);

        $this->assertFalse($result->isSuccessful());
        $this->assertSame('INVALID_MAC', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertNull($result->iterations());
        Phake::verify($decryptTransform, Phake::never())->transform(Phake::anyParameters());
    }

    public function testDecryptFailureBadAesData()
    {
        $data = $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv . 'foobarbazquxdoom';
        $data .= $this->authenticationCode($data);
        $result = $this->cipher->decrypt($this->password, $data);

        $this->assertFalse($result->isSuccessful());
        $this->assertSame('INVALID_PADDING', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertNull($result->iterations());
    }

    public function testDecryptFailureBadPadding()
    {
        $ciphertext = mcrypt_encrypt(
            MCRYPT_RIJNDAEL_128,
            $this->key->encryptionSecret(),
            'foobar',
            MCRYPT_MODE_CBC,
            $this->iv
        );
        $data = $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv . $ciphertext;
        $data .= $this->authenticationCode($data);
        $result = $this->cipher->decrypt($this->password, $data);

        $this->assertFalse($result->isSuccessful());
        $this->assertSame('INVALID_PADDING', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertNull($result->iterations());
    }

    public function testInstance()
    {
        $className = get_class($this->cipher);
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

    protected function authenticationCode($data)
    {
        return hash_hmac(
            'sha256',
            $data,
            $this->key->authenticationSecret(),
            true
        );
    }
}
