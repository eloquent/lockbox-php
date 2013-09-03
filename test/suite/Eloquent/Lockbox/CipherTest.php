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
 * @covers \Eloquent\Lockbox\Cipher
 * @covers \Eloquent\Lockbox\EncryptionCipher
 * @covers \Eloquent\Lockbox\DecryptionCipher
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
        $encrypted = $this->cipher->encrypt($this->privateKey, $data);
        $decrypted = $this->cipher->decrypt($this->privateKey, $encrypted);

        $this->assertSame($data, $decrypted);
    }

    public function testDecryptFailureNotBase64()
    {
        $this->setExpectedException(__NAMESPACE__ . '\Exception\DecryptionFailedException');
        $this->cipher->decrypt($this->privateKey, 'foo:bar');
    }

    public function testDecryptFailureBadData()
    {
        $this->setExpectedException(__NAMESPACE__ . '\Exception\DecryptionFailedException');
        $this->cipher->decrypt($this->privateKey, 'foobar');
    }

    public function testDecryptFailureEmptyKey()
    {
        openssl_public_encrypt('', $data, $this->publicKey->handle(), OPENSSL_PKCS1_OAEP_PADDING);
        $data = $this->base64UriEncode($data);

        $this->setExpectedException(__NAMESPACE__ . '\Exception\DecryptionFailedException');
        $this->cipher->decrypt($this->privateKey, $data);
    }

    public function testDecryptFailureEmptyIv()
    {
        openssl_public_encrypt(
            mcrypt_create_iv(32, MCRYPT_DEV_URANDOM),
            $data,
            $this->publicKey->handle(),
            OPENSSL_PKCS1_OAEP_PADDING
        );
        $data = $this->base64UriEncode($data);

        $this->setExpectedException(__NAMESPACE__ . '\Exception\DecryptionFailedException');
        $this->cipher->decrypt($this->privateKey, $data);
    }

    public function testDecryptFailureBadAesData()
    {
        openssl_public_encrypt(
            mcrypt_create_iv(48, MCRYPT_DEV_URANDOM),
            $data,
            $this->publicKey->handle(),
            OPENSSL_PKCS1_OAEP_PADDING
        );
        $data = $this->base64UriEncode($data . 'foobar');

        $this->setExpectedException(__NAMESPACE__ . '\Exception\DecryptionFailedException');
        $this->cipher->decrypt($this->privateKey, $data);
    }

    public function testDecryptFailureBadPadding()
    {
        $key = mcrypt_create_iv(32, MCRYPT_DEV_URANDOM);
        $iv = mcrypt_create_iv(16, MCRYPT_DEV_URANDOM);

        openssl_public_encrypt($key . $iv, $data, $this->publicKey->handle(), OPENSSL_PKCS1_OAEP_PADDING);
        $data = $this->base64UriEncode(
            $data .
            mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, sha1('foobar', true) . 'foobar' . chr(10), MCRYPT_MODE_CBC, $iv)
        );

        $this->setExpectedException(__NAMESPACE__ . '\Exception\DecryptionFailedException');
        $this->cipher->decrypt($this->privateKey, $data);
    }

    public function testDecryptFailureBadHash()
    {
        $key = mcrypt_create_iv(32, MCRYPT_DEV_URANDOM);
        $iv = mcrypt_create_iv(16, MCRYPT_DEV_URANDOM);

        openssl_public_encrypt($key . $iv, $data, $this->publicKey->handle(), OPENSSL_PKCS1_OAEP_PADDING);
        $data = $this->base64UriEncode(
            $data .
            mcrypt_encrypt(
                MCRYPT_RIJNDAEL_128,
                $key,
                sha1('barfoo', true) . 'foobar' . str_repeat(chr(6), 6),
                MCRYPT_MODE_CBC,
                $iv
            )
        );

        $this->setExpectedException(__NAMESPACE__ . '\Exception\DecryptionFailedException');
        $this->cipher->decrypt($this->privateKey, $data);
    }

    protected function base64UriEncode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
