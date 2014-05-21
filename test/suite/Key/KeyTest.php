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
        //                              encryptSecret                       encryptSecretBits authSecret                                                          authSecretBits
        return array(
            '256 bit, 512 bit' => array('12345678901234567890123456789012', 256,              '1234567890123456789012345678901234567890123456789012345678901234', 512),
            '256 bit, 384 bit' => array('12345678901234567890123456789012', 256,              '123456789012345678901234567890123456789012345678',                 384),
            '256 bit, 256 bit' => array('12345678901234567890123456789012', 256,              '12345678901234567890123456789012',                                 256),
            '256 bit, 224 bit' => array('12345678901234567890123456789012', 256,              '1234567890123456789012345678',                                     224),
            '192 bit, 512 bit' => array('123456789012345678901234',         192,              '1234567890123456789012345678901234567890123456789012345678901234', 512),
            '192 bit, 384 bit' => array('123456789012345678901234',         192,              '123456789012345678901234567890123456789012345678',                 384),
            '192 bit, 256 bit' => array('123456789012345678901234',         192,              '12345678901234567890123456789012',                                 256),
            '192 bit, 224 bit' => array('123456789012345678901234',         192,              '1234567890123456789012345678',                                     224),
            '128 bit, 512 bit' => array('1234567890123456',                 128,              '1234567890123456789012345678901234567890123456789012345678901234', 512),
            '128 bit, 384 bit' => array('1234567890123456',                 128,              '123456789012345678901234567890123456789012345678',                 384),
            '128 bit, 256 bit' => array('1234567890123456',                 128,              '12345678901234567890123456789012',                                 256),
            '128 bit, 224 bit' => array('1234567890123456',                 128,              '1234567890123456789012345678',                                     224),
        );
    }

    /**
     * @dataProvider validSecretData
     */
    public function testConstructor($encryptSecret, $encryptSecretBits, $authSecret, $authSecretBits)
    {
        $this->key = new Key($encryptSecret, $authSecret, 'name', 'description');

        $this->assertSame($encryptSecret, $this->key->encryptSecret());
        $this->assertSame($authSecret, $this->key->authSecret());
        $this->assertSame('name', $this->key->name());
        $this->assertSame('description', $this->key->description());
        $this->assertSame($encryptSecretBits / 8, $this->key->encryptSecretBytes());
        $this->assertSame($encryptSecretBits, $this->key->encryptSecretBits());
        $this->assertSame($authSecretBits / 8, $this->key->authSecretBytes());
        $this->assertSame($authSecretBits, $this->key->authSecretBits());
    }

    public function testNoNameAndDescription()
    {
        $this->key = new Key('1234567890123456', '12345678901234567890123456789012');

        $this->assertNull($this->key->name());
        $this->assertNull($this->key->description());
    }

    public function testInvalidEncryptSecret()
    {
        $this->setExpectedException('Eloquent\Lockbox\Key\Exception\InvalidSecretException');
        new Key(null, '12345678901234567890123456789012');
    }

    public function testInvalidAuthSecret()
    {
        $this->setExpectedException('Eloquent\Lockbox\Key\Exception\InvalidSecretException');
        new Key('12345678901234567890123456789012', null);
    }

    public function testInvalidEncryptSecretSize()
    {
        $this->setExpectedException('Eloquent\Lockbox\Key\Exception\InvalidEncryptSecretSizeException');
        new Key('123456789012345678901234567890123', '12345678901234567890123456789012');
    }

    public function testInvalidAuthSecretSize()
    {
        $this->setExpectedException('Eloquent\Lockbox\Key\Exception\InvalidAuthSecretSizeException');
        new Key('12345678901234567890123456789012', '123456789012345678901234567890123');
    }

    public function testErase()
    {
        $this->key = new Key('1234567890123456', '1234567890123456789012345678', 'name', 'description');
        $this->key->erase();

        $this->assertSame(str_repeat("\0", 16), $this->key->encryptSecret());
        $this->assertSame(str_repeat("\0", 28), $this->key->authSecret());
        $this->assertNull($this->key->name());
        $this->assertNull($this->key->description());
    }
}
