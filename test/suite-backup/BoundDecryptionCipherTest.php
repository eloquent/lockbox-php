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

class BoundDecryptionCipherTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->keyFactory = new Key\KeyFactory;
        $this->key = $this->keyFactory->createPrivateKeyFromFile(
            __DIR__ . '/../fixture/pem/rsa-2048-nopass.private.pem'
        );
        $this->decryptionCipher = new DecryptionCipher;
        $this->cipher = new BoundDecryptionCipher($this->key, $this->decryptionCipher);

        $this->encryptionCipher = new BoundEncryptionCipher($this->key->publicKey());
    }

    public function testConstructor()
    {
        $this->assertSame($this->key, $this->cipher->key());
        $this->assertSame($this->decryptionCipher, $this->cipher->cipher());
    }

    public function testConstructorDefaults()
    {
        $this->cipher = new BoundDecryptionCipher($this->key);

        $this->assertEquals($this->decryptionCipher, $this->cipher->cipher());
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
        $encrypted = $this->encryptionCipher->encrypt($data);
        $decrypted = $this->cipher->decrypt($encrypted);

        $this->assertSame($data, $decrypted);
    }
}
