<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Password;

use Eloquent\Liberator\Liberator;
use Eloquent\Lockbox\Key\KeyDeriver;
use Eloquent\Lockbox\Transform\Factory\PasswordEncryptTransformFactory;
use PHPUnit_Framework_TestCase;
use Phake;

/**
 * @covers \Eloquent\Lockbox\Password\RawPasswordCipher
 * @covers \Eloquent\Lockbox\Password\AbstractPasswordCipher
 * @covers \Eloquent\Lockbox\Password\RawPasswordEncrypter
 * @covers \Eloquent\Lockbox\Password\RawPasswordDecrypter
 */
class RawPasswordCipherTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->randomSource = Phake::mock('Eloquent\Lockbox\Random\RandomSourceInterface');
        $this->encrypter = new RawPasswordEncrypter(
            new PasswordEncryptTransformFactory(new KeyDeriver(null, $this->randomSource))
        );
        $this->decrypter = new RawPasswordDecrypter;
        $this->cipher = new RawPasswordCipher($this->encrypter, $this->decrypter);

        $this->version = chr(1);
        $this->type = chr(2);
        $this->password = 'foobar';
        $this->iterations = 1000;
        $this->salt = '1234567890123456789012345678901234567890123456789012345678901234';

        Phake::when($this->randomSource)->generate(64)->thenReturn($this->salt);
    }

    public function testConstructor()
    {
        $this->assertSame($this->encrypter, $this->cipher->encrypter());
        $this->assertSame($this->decrypter, $this->cipher->decrypter());
    }

    public function testConstructorDefaults()
    {
        $this->cipher = new RawPasswordCipher;

        $this->assertSame(RawPasswordEncrypter::instance(), $this->cipher->encrypter());
        $this->assertSame(RawPasswordDecrypter::instance(), $this->cipher->decrypter());
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
        $encrypted = $this->cipher->encrypt($this->password, $this->iterations, $data);
        $decrypted = $this->cipher->decrypt($this->password, $encrypted);

        $this->assertSame(array($data, $this->iterations), $decrypted);
    }

    /**
     * @dataProvider encryptionData
     */
    public function testEncryptDecryptStreaming($dataSize, $encryptionSecret, $authenticationSecret)
    {
        $encryptStream = $this->cipher->createEncryptStream($this->password, $this->iterations);
        $decryptStream = $this->cipher->createDecryptStream($this->password);
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

    // public function testDecryptFailureEmptyVersion()
    // {
    //     $this->setExpectedException(
    //         'Eloquent\Lockbox\Exception\PasswordDecryptionFailedException',
    //         "Password decryption failed."
    //     );
    //     $this->cipher->decrypt($this->password, '');
    // }

    // public function testDecryptFailureUnsupportedVersion()
    // {
    //     $data = ord(111) . str_pad('', 100, '1234567890');

    //     $this->setExpectedException(
    //         'Eloquent\Lockbox\Exception\PasswordDecryptionFailedException',
    //         "Password decryption failed."
    //     );
    //     $this->cipher->decrypt($this->password, $data);
    // }

    // public function testDecryptFailureEmptyType()
    // {
    //     $data = $this->version;

    //     $this->setExpectedException(
    //         'Eloquent\Lockbox\Exception\PasswordDecryptionFailedException',
    //         "Password decryption failed."
    //     );
    //     $this->cipher->decrypt($this->password, $data);
    // }

    // public function testDecryptUnsupportedType()
    // {
    //     $data = $this->version . ord(111) . str_pad('', 100, '1234567890');

    //     $this->setExpectedException(
    //         'Eloquent\Lockbox\Exception\PasswordDecryptionFailedException',
    //         "Password decryption failed."
    //     );
    //     $this->cipher->decrypt($this->password, $data);
    // }

    // public function testDecryptFailureEmptyIv()
    // {
    //     $data = $this->version . $this->type;

    //     $this->setExpectedException(
    //         'Eloquent\Lockbox\Exception\PasswordDecryptionFailedException',
    //         "Password decryption failed."
    //     );
    //     $this->cipher->decrypt($this->password, $data);
    // }

    // public function testDecryptFailureShortMac()
    // {
    //     $data = $this->version . $this->type . '1234567890123456789012345678901234567890123';

    //     $this->setExpectedException(
    //         'Eloquent\Lockbox\Exception\PasswordDecryptionFailedException',
    //         "Password decryption failed."
    //     );
    //     $this->cipher->decrypt($this->password, $data);
    // }

    // public function testDecryptFailureEmptyCiphertext()
    // {
    //     $data = $this->version . $this->type . '12345678901234567890123456789012345678901234';

    //     $this->setExpectedException(
    //         'Eloquent\Lockbox\Exception\PasswordDecryptionFailedException',
    //         "Password decryption failed."
    //     );
    //     $this->cipher->decrypt($this->password, $data);
    // }

    // public function testDecryptFailureBadMac()
    // {
    //     $data = $this->version . $this->type . '1234567890123456foobar1234567890123456789012345678';

    //     $this->setExpectedException(
    //         'Eloquent\Lockbox\Exception\PasswordDecryptionFailedException',
    //         "Password decryption failed."
    //     );
    //     $this->cipher->decrypt($this->password, $data);
    // }

    // public function testDecryptFailureBadAesData()
    // {
    //     $data = $this->version . $this->type . '1234567890123456foobar' .
    //         $this->authenticationCode($this->key, $this->version . $this->type . '1234567890123456foobar');

    //     $this->setExpectedException(
    //         'Eloquent\Lockbox\Exception\PasswordDecryptionFailedException',
    //         "Password decryption failed."
    //     );
    //     $this->cipher->decrypt($this->password, $data);
    // }

    // public function testDecryptFailureBadPadding()
    // {
    //     $ciphertext = mcrypt_encrypt(
    //         MCRYPT_RIJNDAEL_128,
    //         $this->key->encryptionSecret(),
    //         'foobar',
    //         MCRYPT_MODE_CBC,
    //         '1234567890123456'
    //     );
    //     $data = $this->version . $this->type . '1234567890123456' . $ciphertext .
    //         $this->authenticationCode($this->key, $this->version . $this->type . '1234567890123456' . $ciphertext);

    //     $this->setExpectedException(
    //         'Eloquent\Lockbox\Exception\PasswordDecryptionFailedException',
    //         "Password decryption failed."
    //     );
    //     $this->cipher->decrypt($this->password, $data);
    // }

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
