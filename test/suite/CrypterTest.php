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
use Eloquent\Lockbox\Cipher\Parameters\EncryptParameters;
use PHPUnit_Framework_TestCase;

/**
 * @covers \Eloquent\Lockbox\Crypter
 * @covers \Eloquent\Lockbox\AbstractCrypter
 * @covers \Eloquent\Lockbox\Encrypter
 * @covers \Eloquent\Lockbox\AbstractEncrypter
 * @covers \Eloquent\Lockbox\Decrypter
 * @covers \Eloquent\Lockbox\AbstractDecrypter
 */
class CrypterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->encrypter = new Encrypter;
        $this->decrypter = new Decrypter;
        $this->crypter = new Crypter($this->encrypter, $this->decrypter);

        $this->key = new Key\Key('1234567890123456', '1234567890123456789012345678', 'key');
        $this->parameters = new EncryptParameters($this->key);
        $this->base64Url = Base64Url::instance();
    }

    public function testConstructor()
    {
        $this->assertSame($this->encrypter, $this->crypter->encrypter());
        $this->assertSame($this->decrypter, $this->crypter->decrypter());
    }

    public function testConstructorDefaults()
    {
        $this->crypter = new Crypter;

        $this->assertSame(Encrypter::instance(), $this->crypter->encrypter());
        $this->assertSame(Decrypter::instance(), $this->crypter->decrypter());
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
        $this->parameters = new EncryptParameters($this->key);
        $encrypted = $this->crypter->encrypt($this->parameters, $data);
        $decryptionResult = $this->crypter->decrypt($this->key, $encrypted);

        $this->assertTrue($decryptionResult->isSuccessful());
        $this->assertSame($data, $decryptionResult->data());
    }

    /**
     * @dataProvider encryptionData
     */
    public function testEncryptDecryptStreaming($dataSize, $encryptionSecret, $authenticationSecret)
    {
        $this->key = new Key\Key($encryptionSecret, $authenticationSecret);
        $encryptStream = $this->crypter->createEncryptStream($this->key);
        $decryptStream = $this->crypter->createDecryptStream($this->key);
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

    public function testDecryptFailureNotBase64Url()
    {
        $result = $this->crypter->decrypt($this->key, str_repeat('!', 100));

        $this->assertFalse($result->isSuccessful());
        $this->assertSame('INVALID_ENCODING', $result->type()->key());
        $this->assertNull($result->data());
    }

    public function testInstance()
    {
        $className = get_class($this->crypter);
        Liberator::liberateClass($className)->instance = null;
        $instance = $className::instance();

        $this->assertInstanceOf($className, $instance);
        $this->assertSame($instance, $className::instance());
    }
}
