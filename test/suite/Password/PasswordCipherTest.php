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
 * @covers \Eloquent\Lockbox\Password\PasswordCipher
 * @covers \Eloquent\Lockbox\Password\AbstractPasswordCipher
 * @covers \Eloquent\Lockbox\Password\PasswordEncrypter
 * @covers \Eloquent\Lockbox\Password\PasswordDecrypter
 */
class PasswordCipherTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->randomSource = Phake::mock('Eloquent\Lockbox\Random\RandomSourceInterface');
        $this->keyDeriver = new KeyDeriver(null, $this->randomSource);
        $this->encrypter = new PasswordEncrypter(new PasswordEncryptTransformFactory($this->keyDeriver));
        $this->decrypter = new PasswordDecrypter;
        $this->cipher = new PasswordCipher($this->encrypter, $this->decrypter);

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
        $this->cipher = new PasswordCipher;

        $this->assertSame(PasswordEncrypter::instance(), $this->cipher->encrypter());
        $this->assertSame(PasswordDecrypter::instance(), $this->cipher->decrypter());
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
        $decrypted = $this->cipher->decrypt($this->password, $encrypted);

        $this->assertSame(array($data, $this->iterations), $decrypted);
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

    public function testDecryptFailureNotBase64Url()
    {
        $this->setExpectedException(
            'Eloquent\Lockbox\Exception\PasswordDecryptionFailedException',
            "Password decryption failed."
        );
        $this->cipher->decrypt($this->key, str_repeat('!', 100));
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
