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
 * @covers \Eloquent\Lockbox\Encrypter
 * @covers \Eloquent\Lockbox\Decrypter
 */
class CipherTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->encrypter = new Encrypter;
        $this->decrypter = new Decrypter;
        $this->cipher = new Cipher($this->encrypter, $this->decrypter);

        $this->key = new Key\Key('1234567890123456', '1234567890123456789012345678', 'key');
        $this->base64Url = Base64Url::instance();
    }

    public function testConstructor()
    {
        $this->assertSame($this->encrypter, $this->cipher->encrypter());
        $this->assertSame($this->decrypter, $this->cipher->decrypter());
    }

    public function testConstructorDefaults()
    {
        $this->cipher = new Cipher;

        $this->assertSame(Encrypter::instance(), $this->cipher->encrypter());
        $this->assertSame(Decrypter::instance(), $this->cipher->decrypter());
    }

    public function encryptionData()
    {
        $data = array();
        foreach (array(16, 24, 32) as $encryptionSecretSize) {
            foreach (array(28, 32, 48, 64) as $authenticationSecretSize) {
                foreach (array(0, 1, 1024) as $dataSize) {
                    $label = sprintf(
                        '%d byte(s), %dbit encryption, %dbit authentication',
                        $dataSize,
                        $encryptionSecretSize * 8,
                        $authenticationSecretSize * 8
                    );

                    $data[$label] = array(
                        $dataSize,
                        str_pad('', $encryptionSecretSize, '1234567890'),
                        str_pad('', $authenticationSecretSize, '1234567890'),
                    );
                }
            }
        }

        return $data;
    }

    /**
     * @dataProvider encryptionData
     */
    public function testEncryptDecrypt($dataSize, $encryptionSecret, $authenticationSecret)
    {
        $data = str_repeat('A', $dataSize);
        $this->key = new Key\Key($encryptionSecret, $authenticationSecret);
        $encrypted = $this->cipher->encrypt($this->key, $data);
        $decrypted = $this->cipher->decrypt($this->key, $encrypted);

        $this->assertSame($data, $decrypted);
    }

    public function testDecryptFailureNotBase64Url()
    {
        $this->setExpectedException(
            'Eloquent\Lockbox\Exception\DecryptionFailedException',
            "Decryption failed for key 'key'."
        );
        $this->cipher->decrypt($this->key, str_repeat('!', 100));
    }

    public function testDecryptFailureEmptyIv()
    {
        $this->setExpectedException(
            'Eloquent\Lockbox\Exception\DecryptionFailedException',
            "Decryption failed for key 'key'."
        );
        $this->cipher->decrypt($this->key, '');
    }

    public function testDecryptFailureShortMac()
    {
        $data = $this->base64Url->encode('1234567890123456789012345678901234567890123');

        $this->setExpectedException(
            'Eloquent\Lockbox\Exception\DecryptionFailedException',
            "Decryption failed for key 'key'."
        );
        $this->cipher->decrypt($this->key, $data);
    }

    public function testDecryptFailureEmptyCiphertext()
    {
        $data = $this->base64Url->encode('12345678901234567890123456789012345678901234');

        $this->setExpectedException(
            'Eloquent\Lockbox\Exception\DecryptionFailedException',
            "Decryption failed for key 'key'."
        );
        $this->cipher->decrypt($this->key, $data);
    }

    public function testDecryptFailureBadMac()
    {
        $data = $this->base64Url->encode('1234567890123456foobar1234567890123456789012345678');

        $this->setExpectedException(
            'Eloquent\Lockbox\Exception\DecryptionFailedException',
            "Decryption failed for key 'key'."
        );
        $this->cipher->decrypt($this->key, $data);
    }

    public function testDecryptFailureBadAesData()
    {
        $data = $this->base64Url->encode(
            '1234567890123456foobar' . $this->authenticationCode($this->key, '1234567890123456foobar')
        );

        $this->setExpectedException(
            'Eloquent\Lockbox\Exception\DecryptionFailedException',
            "Decryption failed for key 'key'."
        );
        $this->cipher->decrypt($this->key, $data);
    }

    public function testDecryptFailureBadPadding()
    {
        $ciphertext = mcrypt_encrypt(
            MCRYPT_RIJNDAEL_128,
            $this->key->encryptionSecret(),
            'foobar',
            MCRYPT_MODE_CBC,
            '1234567890123456'
        );
        $data = $this->base64Url->encode(
            '1234567890123456' .
            $ciphertext .
            $this->authenticationCode($this->key, '1234567890123456' . $ciphertext)
        );

        $this->setExpectedException(
            'Eloquent\Lockbox\Exception\DecryptionFailedException',
            "Decryption failed for key 'key'."
        );
        $this->cipher->decrypt($this->key, $data);
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

    protected function authenticationCode($key, $data)
    {
        return hash_hmac(
            'sha' . strlen($key->authenticationSecret()) * 8,
            $data,
            $key->authenticationSecret(),
            true
        );
    }
}
