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
use Eloquent\Lockbox\Crypter;
use Eloquent\Lockbox\Key\Key;
use PHPUnit_Framework_TestCase;

/**
 * @covers \Eloquent\Lockbox\Bound\BoundCrypter
 * @covers \Eloquent\Lockbox\Bound\AbstractBoundCrypter
 */
class BoundCrypterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->decryptParameters = new Key('1234567890123456', '1234567890123456789012345678');
        $this->encryptParameters = new EncryptParameters($this->decryptParameters, '1234567890123456');
        $this->innerCrypter = new Crypter;
        $this->crypter = new BoundCrypter($this->encryptParameters, $this->decryptParameters, $this->innerCrypter);
    }

    public function testConstructor()
    {
        $this->assertSame($this->encryptParameters, $this->crypter->encryptParameters());
        $this->assertSame($this->decryptParameters, $this->crypter->decryptParameters());
        $this->assertSame($this->innerCrypter, $this->crypter->crypter());
    }

    public function testConstructorDefaults()
    {
        $this->crypter = new BoundCrypter($this->encryptParameters, $this->decryptParameters);

        $this->assertSame(Crypter::instance(), $this->crypter->crypter());
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
        $encrypted = $this->crypter->encrypt($data);
        $decryptionResult = $this->crypter->decrypt($encrypted);

        $this->assertTrue($decryptionResult->isSuccessful());
        $this->assertSame($data, $decryptionResult->data());
    }

    /**
     * @dataProvider encryptionData
     */
    public function testEncryptDecryptStreaming($data)
    {
        $encryptStream = $this->crypter->createEncryptStream();
        $decryptStream = $this->crypter->createDecryptStream();
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
