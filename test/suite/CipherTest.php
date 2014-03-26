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

use Eloquent\Endec\Base64\Base64Url;
use Eloquent\Liberator\Liberator;
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

        $this->key128 = new Key\Key('1234567890123456', '12345678901234567890123456789013', 'key128');
        $this->key192 = new Key\Key('123456789012345678901234', '12345678901234567890123456789013', 'key192');
        $this->key256 = new Key\Key('12345678901234567890123456789012', '12345678901234567890123456789013', 'key256');

        $this->base64UrlEncoder = Base64Url::instance();
    }

    public function testConstructor()
    {
        $this->assertSame($this->encryptionCipher, $this->cipher->encryptionCipher());
        $this->assertSame($this->decryptionCipher, $this->cipher->decryptionCipher());
    }

    public function testConstructorDefaults()
    {
        $this->cipher = new Cipher;

        $this->assertSame(EncryptionCipher::instance(), $this->cipher->encryptionCipher());
        $this->assertSame(DecryptionCipher::instance(), $this->cipher->decryptionCipher());
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
    public function testEncryptDecrypt128($data)
    {
        $encrypted = $this->cipher->encrypt($this->key128, $data);
        $decrypted = $this->cipher->decrypt($this->key128, $encrypted);

        $this->assertSame($data, $decrypted);
    }

    /**
     * @dataProvider encryptionData
     */
    public function testEncryptDecrypt192($data)
    {
        $encrypted = $this->cipher->encrypt($this->key192, $data);
        $decrypted = $this->cipher->decrypt($this->key192, $encrypted);

        $this->assertSame($data, $decrypted);
    }

    /**
     * @dataProvider encryptionData
     */
    public function testEncryptDecrypt256($data)
    {
        $encrypted = $this->cipher->encrypt($this->key256, $data);
        $decrypted = $this->cipher->decrypt($this->key256, $encrypted);

        $this->assertSame($data, $decrypted);
    }

    public function testDecryptFailureNotBase64Url()
    {
        $this->setExpectedException(
            'Eloquent\Lockbox\Exception\DecryptionFailedException',
            "Decryption failed for key 'key128'."
        );
        $this->cipher->decrypt($this->key128, 'foo:bar');
    }

    public function testDecryptFailureEmptyIv()
    {
        $this->setExpectedException(
            'Eloquent\Lockbox\Exception\DecryptionFailedException',
            "Decryption failed for key 'key128'."
        );
        $this->cipher->decrypt($this->key128, '');
    }

    public function testDecryptFailureEmptyCiphertext()
    {
        $data = $this->base64UrlEncoder->encode('1234567890123456');

        $this->setExpectedException(
            'Eloquent\Lockbox\Exception\DecryptionFailedException',
            "Decryption failed for key 'key128'."
        );
        $this->cipher->decrypt($this->key128, $data);
    }

    public function testDecryptFailureBadAesData()
    {
        $data = $this->base64UrlEncoder->encode('1234567890123456foobar');

        $this->setExpectedException(
            'Eloquent\Lockbox\Exception\DecryptionFailedException',
            "Decryption failed for key 'key128'."
        );
        $this->cipher->decrypt($this->key128, $data);
    }

    public function testDecryptFailureBadPadding()
    {
        $data = $this->base64UrlEncoder->encode(
            '1234567890123456' .
            mcrypt_encrypt(
                MCRYPT_RIJNDAEL_128,
                $this->key128->encryptionSecret(),
                'foobar' . sha1('barfoo', true),
                MCRYPT_MODE_CBC,
                '1234567890123456'
            )
        );

        $this->setExpectedException(
            'Eloquent\Lockbox\Exception\DecryptionFailedException',
            "Decryption failed for key 'key128'."
        );
        $this->cipher->decrypt($this->key128, $data);
    }

    public function testDecryptFailureEmptyHash()
    {
        $data = $this->base64UrlEncoder->encode(
            '1234567890123456' .
            mcrypt_encrypt(
                MCRYPT_RIJNDAEL_128,
                $this->key128->encryptionSecret(),
                $this->pad(''),
                MCRYPT_MODE_CBC,
                '1234567890123456'
            )
        );

        $this->setExpectedException(
            'Eloquent\Lockbox\Exception\DecryptionFailedException',
            "Decryption failed for key 'key128'."
        );
        $this->cipher->decrypt($this->key128, $data);
    }

    public function testDecryptFailureBadHash()
    {
        $data = $this->base64UrlEncoder->encode(
            '1234567890123456' .
            mcrypt_encrypt(
                MCRYPT_RIJNDAEL_128,
                $this->key128->encryptionSecret(),
                $this->pad('foobar' . sha1('barfoo', true)),
                MCRYPT_MODE_CBC,
                '1234567890123456'
            )
        );

        $this->setExpectedException(
            'Eloquent\Lockbox\Exception\DecryptionFailedException',
            "Decryption failed for key 'key128'."
        );
        $this->cipher->decrypt($this->key128, $data);
    }

    public function testInstance()
    {
        $className = get_class($this->cipher);
        Liberator::liberateClass($className)->instance = null;
        $instance = $className::instance();

        $this->assertInstanceOf($className, $instance);
        $this->assertSame($instance, $className::instance());
    }

    protected function pad($data)
    {
        $padSize = intval(16 - (strlen($data) % 16));

        return $data . str_repeat(chr($padSize), $padSize);
    }
}
