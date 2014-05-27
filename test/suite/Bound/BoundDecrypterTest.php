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

use Eloquent\Lockbox\Decrypter;
use Eloquent\Lockbox\Key\Key;
use PHPUnit_Framework_TestCase;

/**
 * @covers \Eloquent\Lockbox\Bound\BoundDecrypter
 * @covers \Eloquent\Lockbox\Bound\AbstractBoundDecrypter
 */
class BoundDecrypterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->parameters = new Key('1234567890123456', '1234567890123456789012345678');
        $this->innerDecrypter = new Decrypter;
        $this->decrypter = new BoundDecrypter($this->parameters, $this->innerDecrypter);

        $this->encrypter = new BoundEncrypter($this->parameters);
    }

    public function testConstructor()
    {
        $this->assertSame($this->parameters, $this->decrypter->parameters());
        $this->assertSame($this->innerDecrypter, $this->decrypter->decrypter());
    }

    public function testConstructorDefaults()
    {
        $this->decrypter = new BoundDecrypter($this->parameters);

        $this->assertSame(Decrypter::instance(), $this->decrypter->decrypter());
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
