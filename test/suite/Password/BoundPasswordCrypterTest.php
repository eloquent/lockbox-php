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

use Eloquent\Lockbox\Password\Cipher\Parameters\PasswordDecryptParameters;
use Eloquent\Lockbox\Password\Cipher\Parameters\PasswordEncryptParameters;
use PHPUnit_Framework_TestCase;

class BoundPasswordCrypterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->encryptParameters = new PasswordEncryptParameters('password', 10);
        $this->decryptParameters = new PasswordDecryptParameters('password');
        $this->innerCrypter = new PasswordCrypter;
        $this->crypter = new BoundPasswordCrypter(
            $this->encryptParameters,
            $this->decryptParameters,
            $this->innerCrypter
        );
    }

    public function testConstructor()
    {
        $this->assertSame($this->encryptParameters, $this->crypter->encryptParameters());
        $this->assertSame($this->decryptParameters, $this->crypter->decryptParameters());
        $this->assertSame($this->innerCrypter, $this->crypter->crypter());
    }

    public function testConstructorDefaults()
    {
        $this->crypter = new BoundPasswordCrypter($this->encryptParameters, $this->decryptParameters);

        $this->assertSame(PasswordCrypter::instance(), $this->crypter->crypter());
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
        $encrypted = $this->crypter->encrypt($data);
        $decryptionResult = $this->crypter->decrypt($encrypted);

        $this->assertTrue($decryptionResult->isSuccessful());
        $this->assertSame($data, $decryptionResult->data());
        $this->assertSame(10, $decryptionResult->iterations());
    }

    /**
     * @dataProvider encryptionData
     */
    public function testEncryptDecryptStreaming($data)
    {
        $encryptStream = $this->crypter->createEncryptStream();
        $decryptStream = $this->crypter->createDecryptStream();
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
