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

use Eloquent\Liberator\Liberator;
use PHPUnit_Framework_TestCase;

/**
 * @covers \Eloquent\Lockbox\RawCipher
 * @covers \Eloquent\Lockbox\AbstractCipher
 * @covers \Eloquent\Lockbox\RawEncrypter
 * @covers \Eloquent\Lockbox\RawDecrypter
 */
class RawCipherTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->encrypter = new RawEncrypter;
        $this->decrypter = new RawDecrypter;
        $this->cipher = new RawCipher($this->encrypter, $this->decrypter);

        $this->version = pack('n', 1);
        $this->key = new Key\Key('1234567890123456', '1234567890123456789012345678', 'key');
    }

    public function testConstructor()
    {
        $this->assertSame($this->encrypter, $this->cipher->encrypter());
        $this->assertSame($this->decrypter, $this->cipher->decrypter());
    }

    public function testConstructorDefaults()
    {
        $this->cipher = new RawCipher;

        $this->assertSame(RawEncrypter::instance(), $this->cipher->encrypter());
        $this->assertSame(RawDecrypter::instance(), $this->cipher->decrypter());
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

    public function testDecryptFailureEmptyVersion()
    {
        $this->setExpectedException(
            'Eloquent\Lockbox\Exception\DecryptionFailedException',
            "Decryption failed for key 'key'."
        );
        $this->cipher->decrypt($this->key, '');
    }

    public function testDecryptFailureUnsupportedVersion()
    {
        $data = pack('n', 111) . str_pad('', 100, '1234567890');

        $this->setExpectedException(
            'Eloquent\Lockbox\Exception\DecryptionFailedException',
            "Decryption failed for key 'key'."
        );
        $this->cipher->decrypt($this->key, $data);
    }

    public function testDecryptFailureEmptyIv()
    {
        $data = $this->version;

        $this->setExpectedException(
            'Eloquent\Lockbox\Exception\DecryptionFailedException',
            "Decryption failed for key 'key'."
        );
        $this->cipher->decrypt($this->key, $data);
    }

    public function testDecryptFailureShortMac()
    {
        $data = $this->version . '1234567890123456789012345678901234567890123';

        $this->setExpectedException(
            'Eloquent\Lockbox\Exception\DecryptionFailedException',
            "Decryption failed for key 'key'."
        );
        $this->cipher->decrypt($this->key, $data);
    }

    public function testDecryptFailureEmptyCiphertext()
    {
        $data = $this->version . '12345678901234567890123456789012345678901234';

        $this->setExpectedException(
            'Eloquent\Lockbox\Exception\DecryptionFailedException',
            "Decryption failed for key 'key'."
        );
        $this->cipher->decrypt($this->key, $data);
    }

    public function testDecryptFailureBadMac()
    {
        $data = $this->version . '1234567890123456foobar1234567890123456789012345678';

        $this->setExpectedException(
            'Eloquent\Lockbox\Exception\DecryptionFailedException',
            "Decryption failed for key 'key'."
        );
        $this->cipher->decrypt($this->key, $data);
    }

    public function testDecryptFailureBadAesData()
    {
        $data = $this->version .
            '1234567890123456foobar' .
            $this->authenticationCode($this->key, $this->version . '1234567890123456foobar');

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
        $data = $this->version .
            '1234567890123456' .
            $ciphertext .
            $this->authenticationCode($this->key, $this->version . '1234567890123456' . $ciphertext);

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
