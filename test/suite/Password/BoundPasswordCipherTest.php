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

use PHPUnit_Framework_TestCase;

class BoundPasswordCipherTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->innerCipher = new PasswordCipher;
        $this->cipher = new BoundPasswordCipher('password', 10, $this->innerCipher);
    }

    public function testConstructor()
    {
        $this->assertSame('password', $this->cipher->password());
        $this->assertSame(10, $this->cipher->iterations());
        $this->assertSame($this->innerCipher, $this->cipher->cipher());
    }

    public function testConstructorDefaults()
    {
        $this->cipher = new BoundPasswordCipher('password', 10);

        $this->assertSame(PasswordCipher::instance(), $this->cipher->cipher());
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
        $encrypted = $this->cipher->encrypt($data);
        $decryptionResult = $this->cipher->decrypt($encrypted);

        $this->assertTrue($decryptionResult->isSuccessful());
        $this->assertSame($data, $decryptionResult->data());
        $this->assertSame(10, $decryptionResult->iterations());
    }

    /**
     * @dataProvider encryptionData
     */
    public function testEncryptDecryptStreaming($data)
    {
        $encryptStream = $this->cipher->createEncryptStream();
        $decryptStream = $this->cipher->createDecryptStream();
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
