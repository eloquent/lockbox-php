<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Eloquent\Lockbox;

use PHPUnit_Framework_TestCase;

/**
 * @covers Eloquent\Lockbox\Cipher
 * @covers Eloquent\Lockbox\EncryptionCipher
 * @covers Eloquent\Lockbox\DecryptionCipher
 */
class CipherTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->encryptionCipher = new EncryptionCipher;
        $this->decryptionCipher = new DecryptionCipher;
        $this->cipher = new Cipher($this->encryptionCipher, $this->decryptionCipher);

        $this->keyFactory = new Key\KeyFactory;
        $this->privateKey = $this->keyFactory->createPrivateKeyFromFile(
            __DIR__ . '/../../../fixture/pem/rsa-2048-nopass.private.pem'
        );
        $this->publicKey = $this->privateKey->publicKey();
    }

    public function testConstructor()
    {
        $this->assertSame($this->encryptionCipher, $this->cipher->encryptionCipher());
        $this->assertSame($this->decryptionCipher, $this->cipher->decryptionCipher());
    }

    public function testConstructorDefaults()
    {
        $this->cipher = new Cipher;

        $this->assertEquals($this->encryptionCipher, $this->cipher->encryptionCipher());
        $this->assertEquals($this->decryptionCipher, $this->cipher->decryptionCipher());
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
        $encrypted = $this->cipher->encrypt($this->publicKey, $data);
        $decrypted = $this->cipher->decrypt($this->privateKey, $encrypted);

        $this->assertSame($data, $decrypted);
    }
}
