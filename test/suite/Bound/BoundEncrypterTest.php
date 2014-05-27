<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Bound;

use Eloquent\Lockbox\Cipher\Parameters\EncryptParameters;
use Eloquent\Lockbox\Encrypter;
use Eloquent\Lockbox\Key\Key;
use PHPUnit_Framework_TestCase;

/**
 * @covers \Eloquent\Lockbox\Bound\BoundEncrypter
 * @covers \Eloquent\Lockbox\Bound\AbstractBoundEncrypter
 */
class BoundEncrypterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->decryptParameters = new Key('1234567890123456', '1234567890123456789012345678');
        $this->parameters = new EncryptParameters($this->decryptParameters, '1234567890123456');
        $this->innerEncrypter = new Encrypter;
        $this->encrypter = new BoundEncrypter($this->parameters, $this->innerEncrypter);

        $this->decrypter = new BoundDecrypter($this->decryptParameters);
    }

    public function testConstructor()
    {
        $this->assertSame($this->parameters, $this->encrypter->parameters());
        $this->assertSame($this->innerEncrypter, $this->encrypter->encrypter());
    }

    public function testConstructorDefaults()
    {
        $this->encrypter = new BoundEncrypter($this->parameters);

        $this->assertSame(Encrypter::instance(), $this->encrypter->encrypter());
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
        $encrypted = $this->encrypter->encrypt($data);
        $decryptionResult = $this->decrypter->decrypt($encrypted);

        $this->assertTrue($decryptionResult->isSuccessful());
        $this->assertSame($data, $decryptionResult->data());
    }

    /**
     * @dataProvider encryptionData
     */
    public function testEncryptDecryptStreaming($data)
    {
        $encryptStream = $this->encrypter->createEncryptStream();
        $decryptStream = $this->decrypter->createDecryptStream();
        $encryptStream->pipe($decryptStream);
        $decrypted = '';
        $decryptStream->on(
            'data',
            function ($data, $stream) use (&$decrypted) {
                $decrypted .= $data;
            }
        );
        $data = '';
        foreach (str_split($data) as $byte) {
            $encryptStream->write($byte);
        }
        $encryptStream->end();

        $this->assertSame($data, $decrypted);
    }
}
