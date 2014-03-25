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

class BoundCipherTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->keyFactory = new Key\KeyFactory;
        $this->privateKey = $this->keyFactory->createPrivateKeyFromFile(
            __DIR__ . '/../fixture/pem/rsa-2048-nopass.private.pem'
        );
        $this->encryptionCipher = new EncryptionCipher;
        $this->decryptionCipher = new DecryptionCipher;
        $this->cipher = new BoundCipher($this->privateKey, $this->encryptionCipher, $this->decryptionCipher);

        $this->publicKey = $this->privateKey->publicKey();
    }

    public function testConstructor()
    {
        $this->assertSame($this->privateKey, $this->cipher->privateKey());
        $this->assertSame($this->encryptionCipher, $this->cipher->encryptionCipher());
        $this->assertSame($this->decryptionCipher, $this->cipher->decryptionCipher());
        $this->assertSame($this->publicKey->string(), $this->cipher->publicKey()->string());
    }

    public function testConstructorDefaults()
    {
        $this->cipher = new BoundCipher($this->privateKey);

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
        $encrypted = $this->cipher->encrypt($data);
        $decrypted = $this->cipher->decrypt($encrypted);

        $this->assertSame($data, $decrypted);
    }
}
