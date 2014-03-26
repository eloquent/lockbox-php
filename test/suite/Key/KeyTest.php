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

    public function validEncryptionSecretData()
    {
        return array(
            '256 bit' => array('12345678901234567890123456789012', 256),
            '192 bit' => array('123456789012345678901234',         192),
            '128 bit' => array('1234567890123456',                 128),
        );
    }

    /**
     * @dataProvider validEncryptionSecretData
     */
    public function testConstructor($encryptionSecret, $encryptionSecretSize)
    {
        $this->key = new Key(
            $encryptionSecret,
            '12345678901234567890123456789012',
            'name',
            'description'
        );

        $this->assertSame($encryptionSecret, $this->key->encryptionSecret());
        $this->assertSame('12345678901234567890123456789012', $this->key->authenticationSecret());
        $this->assertSame('name', $this->key->name());
        $this->assertSame('description', $this->key->description());
        $this->assertSame($encryptionSecretSize, $this->key->encryptionSecretSize());
        $this->assertSame(256, $this->key->authenticationSecretSize());
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
