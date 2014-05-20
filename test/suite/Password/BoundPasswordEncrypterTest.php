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

use Eloquent\Lockbox\Password\Cipher\Parameters\PasswordEncryptParameters;
use PHPUnit_Framework_TestCase;

/**
 * @covers \Eloquent\Lockbox\Password\BoundPasswordEncrypter
 * @covers \Eloquent\Lockbox\AbstractBoundEncrypter
 */
class BoundPasswordEncrypterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->decryptParameters = new Password('password');
        $this->parameters = new PasswordEncryptParameters($this->decryptParameters, 10);
        $this->innerEncrypter = new PasswordEncrypter;
        $this->encrypter = new BoundPasswordEncrypter($this->parameters, $this->innerEncrypter);

        $this->decrypter = new BoundPasswordDecrypter($this->decryptParameters);
    }

    public function testConstructor()
    {
        $this->assertSame($this->parameters, $this->encrypter->parameters());
        $this->assertSame($this->innerEncrypter, $this->encrypter->encrypter());
    }

    public function testConstructorDefaults()
    {
        $this->encrypter = new BoundPasswordEncrypter($this->parameters);

        $this->assertSame(PasswordEncrypter::instance(), $this->encrypter->encrypter());
    }

    public function encryptionData()
    {
        return array(
            'Empty string' => array(''),
            'Short data'   => array('foobar'),
            'Long data'    => array(str_repeat('A', 8192)),
        );
    }

    /**
     * @dataProvider encryptionData
     */
    public function testEncryptDecrypt($data)
    {
        $encrypted = $this->encrypter->encrypt($data);
        $decryptionResult = $this->decrypter->decrypt($encrypted);

        $this->assertTrue($decryptionResult->isSuccessful());
        $this->assertSame($data, $decryptionResult->data());
        $this->assertSame(10, $decryptionResult->iterations());
    }

    /**
     * @dataProvider encryptionData
     */
    public function testEncryptDecryptStreaming($data)
    {
        $encryptStream = $this->encrypter->createEncryptStream();
        $decryptStream = $this->decrypter->createDecryptStream();
        $encryptStream->pipe($decryptStream);
        $decrypted = '';
        $decryptStream->on(
            'data',
            function ($data, $stream) use (&$decrypted) {
                $decrypted .= $data;
            }
        );
        $data = '';
        foreach (str_split($data) as $byte) {
            $encryptStream->write($byte);
        }
        $encryptStream->end();

        $this->assertSame($data, $decrypted);
    }
}
