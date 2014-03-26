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

class BoundCipherTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->key = new Key\Key('1234567890123456', '12345678901234567890123456789012');
        $this->encrypter = new Encrypter;
        $this->decrypter = new Decrypter;
        $this->cipher = new BoundCipher($this->key, $this->encrypter, $this->decrypter);
    }

    public function testConstructor()
    {
        $this->assertSame($this->key, $this->cipher->key());
        $this->assertSame($this->encrypter, $this->cipher->encrypter());
        $this->assertSame($this->decrypter, $this->cipher->decrypter());
    }

    public function testConstructorDefaults()
    {
        $this->cipher = new BoundCipher($this->key);

        $this->assertEquals($this->encrypter, $this->cipher->encrypter());
        $this->assertEquals($this->decrypter, $this->cipher->decrypter());
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
        $decrypted = $this->cipher->decrypt($encrypted);

        $this->assertSame($data, $decrypted);
    }
}
