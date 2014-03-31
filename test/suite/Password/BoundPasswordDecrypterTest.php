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

class BoundPasswordDecrypterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->innerDecrypter = new PasswordDecrypter;
        $this->decrypter = new BoundPasswordDecrypter('password', $this->innerDecrypter);

        $this->encrypter = new BoundPasswordEncrypter('password', 10);
    }

    public function testConstructor()
    {
        $this->assertSame('password', $this->decrypter->password());
        $this->assertSame($this->innerDecrypter, $this->decrypter->decrypter());
    }

    public function testConstructorDefaults()
    {
        $this->decrypter = new BoundPasswordDecrypter('password');

        $this->assertSame(PasswordDecrypter::instance(), $this->decrypter->decrypter());
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
        $decrypted = $this->decrypter->decrypt($encrypted);

        $this->assertSame(array($data, 10), $decrypted);
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
