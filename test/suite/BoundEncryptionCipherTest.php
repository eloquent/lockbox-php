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

class BoundEncryptionCipherTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->key = new Key\Key('1234567890123456');
        $this->encryptionCipher = new EncryptionCipher;
        $this->cipher = new BoundEncryptionCipher($this->key, $this->encryptionCipher);

        $this->decryptionCipher = new BoundDecryptionCipher($this->key);
    }

    public function testConstructor()
    {
        $this->assertSame($this->key, $this->cipher->key());
        $this->assertSame($this->encryptionCipher, $this->cipher->cipher());
    }

    public function testConstructorDefaults()
    {
        $this->cipher = new BoundEncryptionCipher($this->key);

        $this->assertEquals($this->encryptionCipher, $this->cipher->cipher());
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
        $decrypted = $this->decryptionCipher->decrypt($encrypted);

        $this->assertSame($data, $decrypted);
    }
}
