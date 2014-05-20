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
use Eloquent\Lockbox\Password\Cipher\Parameters\PasswordEncryptParameters;
use PHPUnit_Framework_TestCase;

/**
 * @covers \Eloquent\Lockbox\Password\PasswordCrypter
 * @covers \Eloquent\Lockbox\AbstractCrypter
 * @covers \Eloquent\Lockbox\Password\PasswordEncrypter
 * @covers \Eloquent\Lockbox\AbstractEncrypter
 * @covers \Eloquent\Lockbox\Password\PasswordDecrypter
 * @covers \Eloquent\Lockbox\AbstractDecrypter
 */
class PasswordCrypterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->encrypter = new PasswordEncrypter;
        $this->decrypter = new PasswordDecrypter;
        $this->crypter = new PasswordCrypter($this->encrypter, $this->decrypter);

        $this->decryptParameters = new Password('foobar');
        $this->iterations = 10;
        $this->salt = '1234567890123456789012345678901234567890123456789012345678901234';
        $this->iv = '1234567890123456';
        $this->encryptParameters = new PasswordEncryptParameters(
            $this->decryptParameters,
            $this->iterations,
            $this->salt,
            $this->iv
        );
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
}
