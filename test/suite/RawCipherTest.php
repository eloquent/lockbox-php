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
use Eloquent\Lockbox\Exception\DecryptionFailedException;
use PHPUnit_Framework_TestCase;
use Phake;

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

        $this->version = $this->type = chr(1);
        $this->iv = '1234567890123456';
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
        foreach (array(16, 24, 32) as $encryptionSecretBytes) {
            foreach (array(28, 32, 48, 64) as $authenticationSecretBytes) {
                foreach (array(0, 1, 1024) as $dataSize) {
                    $label = sprintf(
                        '%d byte(s), %dbit encryption, %dbit authentication',
                        $dataSize,
                        $encryptionSecretBytes * 8,
                        $authenticationSecretBytes * 8
                    );

                    $data[$label] = array(
                        $dataSize,
                        str_pad('', $encryptionSecretBytes, '1234567890'),
                        str_pad('', $authenticationSecretBytes, '1234567890'),
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

    /**
     * @dataProvider encryptionData
     */
    public function testEncryptDecryptStreaming($dataSize, $encryptionSecret, $authenticationSecret)
    {
        $this->key = new Key\Key($encryptionSecret, $authenticationSecret);
        $encryptStream = $this->cipher->createEncryptStream($this->key);
        $decryptStream = $this->cipher->createDecryptStream($this->key);
        $encryptStream->pipe($decryptStream);
        $decrypted = '';
        $decryptStream->on(
            'data',
            function ($data, $stream) use (&$decrypted) {
                $decrypted .= $data;
            }
        );
        $data = '';
        for ($i = 0; $i < $dataSize; $i ++) {
            $data .= 'A';
            $encryptStream->write('A');
        }
        $encryptStream->end();

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
        $data = ord(111) . str_pad('', 100, '1234567890');

        $this->setExpectedException(
            'Eloquent\Lockbox\Exception\DecryptionFailedException',
            "Decryption failed for key 'key'."
        );
        $this->cipher->decrypt($this->key, $data);
    }

    public function testDecryptFailureEmptyType()
    {
        $data = $this->version;

        $this->setExpectedException(
            'Eloquent\Lockbox\Exception\DecryptionFailedException',
            "Decryption failed for key 'key'."
        );
        $this->cipher->decrypt($this->key, $data);
    }

    public function testDecryptUnsupportedType()
    {
        $data = $this->version . ord(111) . str_pad('', 100, '1234567890');

        $this->setExpectedException(
            'Eloquent\Lockbox\Exception\DecryptionFailedException',
            "Decryption failed for key 'key'."
        );
        $this->cipher->decrypt($this->key, $data);
    }

    public function testDecryptFailureEmptyIv()
    {
        $data = $this->version . $this->type;

        $this->setExpectedException(
            'Eloquent\Lockbox\Exception\DecryptionFailedException',
            "Decryption failed for key 'key'."
        );
        $this->cipher->decrypt($this->key, $data);
    }

    public function testDecryptFailureShortMac()
    {
        $data = $this->version . $this->type . $this->iv . '789012345678901234567890123';

        $this->setExpectedException(
            'Eloquent\Lockbox\Exception\DecryptionFailedException',
            "Decryption failed for key 'key'."
        );
        $this->cipher->decrypt($this->key, $data);
    }

    public function testDecryptFailureEmptyCiphertext()
    {
        $data = $this->version . $this->type . $this->iv . '7890123456789012345678901234';

        $this->setExpectedException(
            'Eloquent\Lockbox\Exception\DecryptionFailedException',
            "Decryption failed for key 'key'."
        );
        $this->cipher->decrypt($this->key, $data);
    }

    public function testDecryptFailureBadMac()
    {
        $decryptTransformFactory = Phake::partialMock('Eloquent\Lockbox\Transform\Factory\KeyTransformFactoryInterface');
        $decryptTransform = Phake::partialMock('Eloquent\Lockbox\Transform\DecryptTransform', $this->key);
        $this->decrypter = new RawDecrypter($decryptTransformFactory);
        $this->cipher = new Cipher($this->encrypter, $this->decrypter);
        Phake::when($decryptTransformFactory)->createTransform($this->key)->thenReturn($decryptTransform);
        $data = $this->version . $this->type . $this->iv . 'foobar1234567890123456789012345678';

        $e = null;
        try {
            $this->cipher->decrypt($this->key, $data);
        } catch (DecryptionFailedException $e) {}
        Phake::verify($decryptTransform, Phake::never())->transform(Phake::anyParameters());
        $this->setExpectedException(
            'Eloquent\Lockbox\Exception\DecryptionFailedException',
            "Decryption failed for key 'key'."
        );
        if (null !== $e) {
            throw $e;
        }
    }

    public function testDecryptFailureBadAesData()
    {
        $data = $this->version . $this->type . $this->iv . 'foobar' .
            $this->authenticationCode($this->key, $this->version . $this->type . $this->iv . 'foobar');

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
            $this->iv
        );
        $data = $this->version . $this->type . $this->iv . $ciphertext .
            $this->authenticationCode($this->key, $this->version . $this->type . $this->iv . $ciphertext);

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
