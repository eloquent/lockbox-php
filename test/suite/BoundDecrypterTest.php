<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox;

use PHPUnit_Framework_TestCase;

class BoundDecrypterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->key = new Key\Key('1234567890123456', '12345678901234567890123456789012');
        $this->innerDecrypter = new Decrypter;
        $this->decrypter = new BoundDecrypter($this->key, $this->innerDecrypter);

        $this->encrypter = new BoundEncrypter($this->key);
    }

    public function testConstructor()
    {
        $this->assertSame($this->key, $this->decrypter->key());
        $this->assertSame($this->innerDecrypter, $this->decrypter->decrypter());
    }

    public function testConstructorDefaults()
    {
        $this->decrypter = new BoundDecrypter($this->key);

        $this->assertSame(Decrypter::instance(), $this->decrypter->decrypter());
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
