<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Key;

use PHPUnit_Framework_TestCase;

class KeyTest extends PHPUnit_Framework_TestCase
{
    public function validSecretData()
    {
        //                              encryptionSecret                    encryptionSecretBits authenticationSecret                                                authenticationSecretBits
        return array(
            '256 bit, 512 bit' => array('12345678901234567890123456789012', 256,                 '1234567890123456789012345678901234567890123456789012345678901234', 512),
            '256 bit, 384 bit' => array('12345678901234567890123456789012', 256,                 '123456789012345678901234567890123456789012345678',                 384),
            '256 bit, 256 bit' => array('12345678901234567890123456789012', 256,                 '12345678901234567890123456789012',                                 256),
            '256 bit, 224 bit' => array('12345678901234567890123456789012', 256,                 '1234567890123456789012345678',                                     224),
            '192 bit, 512 bit' => array('123456789012345678901234',         192,                 '1234567890123456789012345678901234567890123456789012345678901234', 512),
            '192 bit, 384 bit' => array('123456789012345678901234',         192,                 '123456789012345678901234567890123456789012345678',                 384),
            '192 bit, 256 bit' => array('123456789012345678901234',         192,                 '12345678901234567890123456789012',                                 256),
            '192 bit, 224 bit' => array('123456789012345678901234',         192,                 '1234567890123456789012345678',                                     224),
            '128 bit, 512 bit' => array('1234567890123456',                 128,                 '1234567890123456789012345678901234567890123456789012345678901234', 512),
            '128 bit, 384 bit' => array('1234567890123456',                 128,                 '123456789012345678901234567890123456789012345678',                 384),
            '128 bit, 256 bit' => array('1234567890123456',                 128,                 '12345678901234567890123456789012',                                 256),
            '128 bit, 224 bit' => array('1234567890123456',                 128,                 '1234567890123456789012345678',                                     224),
        );
    }

    /**
     * @dataProvider validSecretData
     */
    public function testConstructor($encryptionSecret, $encryptionSecretBits, $authenticationSecret, $authenticationSecretBits)
    {
        $this->key = new Key(
            $encryptionSecret,
            $authenticationSecret,
            'name',
            'description'
        );

        $this->assertSame($encryptionSecret, $this->key->encryptionSecret());
        $this->assertSame($authenticationSecret, $this->key->authenticationSecret());
        $this->assertSame('name', $this->key->name());
        $this->assertSame('description', $this->key->description());
        $this->assertSame($encryptionSecretBits / 8, $this->key->encryptionSecretBytes());
        $this->assertSame($encryptionSecretBits, $this->key->encryptionSecretBits());
        $this->assertSame($authenticationSecretBits / 8, $this->key->authenticationSecretBytes());
        $this->assertSame($authenticationSecretBits, $this->key->authenticationSecretBits());
    }

    public function testNoNameAndDescription()
    {
        $this->key = new Key('1234567890123456', '12345678901234567890123456789012');

        $this->assertNull($this->key->name());
        $this->assertNull($this->key->description());
    }

    public function testInvalidEncryptionSecret()
    {
        $this->setExpectedException('Eloquent\Lockbox\Key\Exception\InvalidSecretException');
        new Key(null, '12345678901234567890123456789012');
    }

    public function testInvalidAuthenticationSecret()
    {
        $this->setExpectedException('Eloquent\Lockbox\Key\Exception\InvalidSecretException');
        new Key('12345678901234567890123456789012', null);
    }

    public function testInvalidEncryptionSecretSize()
    {
        $this->setExpectedException('Eloquent\Lockbox\Key\Exception\InvalidEncryptionSecretSizeException');
        new Key('123456789012345678901234567890123', '12345678901234567890123456789012');
    }

    public function testInvalidAuthenticationSecretSize()
    {
        $this->setExpectedException('Eloquent\Lockbox\Key\Exception\InvalidAuthenticationSecretSizeException');
        new Key('12345678901234567890123456789012', '123456789012345678901234567890123');
    }
}
