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
use Eloquent\Lockbox\Password\Cipher\Factory\PasswordEncryptCipherFactory;
use Eloquent\Lockbox\Password\Cipher\Parameters\PasswordDecryptCipherParameters;
use Eloquent\Lockbox\Password\Cipher\Parameters\PasswordEncryptCipherParameters;
use PHPUnit_Framework_TestCase;
use Phake;

/**
 * @covers \Eloquent\Lockbox\Password\PasswordCrypter
 * @covers \Eloquent\Lockbox\Password\PasswordEncrypter
 * @covers \Eloquent\Lockbox\Password\PasswordDecrypter
 */
class PasswordCrypterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->randomSource = Phake::mock('Eloquent\Lockbox\Random\RandomSourceInterface');
        $this->keyDeriver = new KeyDeriver(null, $this->randomSource);
        $this->encrypter = new PasswordEncrypter(new PasswordEncryptCipherFactory($this->keyDeriver));
        $this->decrypter = new PasswordDecrypter;
        $this->crypter = new PasswordCrypter($this->encrypter, $this->decrypter);

        $this->version = chr(1);
        $this->type = chr(2);
        $this->password = 'foobar';
        $this->iterations = 10;
        $this->encryptParameters = new PasswordEncryptCipherParameters($this->password, $this->iterations);
        $this->decryptParameters = new PasswordDecryptCipherParameters($this->password);
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
        $this->crypter = new PasswordCrypter;

        $this->assertSame(PasswordEncrypter::instance(), $this->crypter->encrypter());
        $this->assertSame(PasswordDecrypter::instance(), $this->crypter->decrypter());
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
        $encrypted = $this->crypter->encrypt($this->encryptParameters, $data);
        $decryptionResult = $this->crypter->decrypt($this->decryptParameters, $encrypted);

        $this->assertTrue($decryptionResult->isSuccessful());
        $this->assertSame($data, $decryptionResult->data());
        $this->assertSame($this->iterations, $decryptionResult->iterations());
    }

    /**
     * @dataProvider encryptionData
     */
    public function testEncryptDecryptStreaming($dataSize)
    {
        $encryptStream = $this->crypter->createEncryptStream($this->encryptParameters);
        $decryptStream = $this->crypter->createDecryptStream($this->decryptParameters);
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

    public function testDecryptFailureNotBase64Url()
    {
        $result = $this->crypter->decrypt($this->decryptParameters, str_repeat('!', 100));

        $this->assertFalse($result->isSuccessful());
        $this->assertSame('INVALID_ENCODING', $result->type()->key());
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
