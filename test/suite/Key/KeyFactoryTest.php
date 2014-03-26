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

use Eloquent\Liberator\Liberator;
use PHPUnit_Framework_TestCase;

class KeyFactoryTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->factory = new KeyFactory;
    }

    public function validEncryptionSecretData()
    {
        return array(
            '256 bit' => array('12345678901234567890123456789012'),
            '192 bit' => array('123456789012345678901234'),
            '128 bit' => array('1234567890123456'),
        );
    }

    /**
     * @dataProvider validEncryptionSecretData
     */
    public function testCreateKey($encryptionSecret)
    {
        $this->key = $this->factory->createKey(
            $encryptionSecret,
            '12345678901234567890123456789012',
            'name',
            'description'
        );

        $this->assertSame($encryptionSecret, $this->key->encryptionSecret());
        $this->assertSame('12345678901234567890123456789012', $this->key->authenticationSecret());
        $this->assertSame('name', $this->key->name());
        $this->assertSame('description', $this->key->description());
    }

    public function testCreateKeyNoNameAndDescription()
    {
        $this->key = $this->factory->createKey('1234567890123456', '12345678901234567890123456789012');

        $this->assertNull($this->key->name());
        $this->assertNull($this->key->description());
    }

    public function testCreateKeyInvalidEncryptionSecretSize()
    {
        $this->setExpectedException('Eloquent\Lockbox\Key\Exception\InvalidEncryptionSecretSizeException');
        $this->factory->createKey('123456789012345678901234567890123', '12345678901234567890123456789012');
    }

    public function testCreateKeyInvalidAuthenticationSecretSize()
    {
        $this->setExpectedException('Eloquent\Lockbox\Key\Exception\InvalidAuthenticationSecretSizeException');
        $this->factory->createKey('12345678901234567890123456789012', '123456789012345678901234567890123');
    }

    public function testInstance()
    {
        $className = get_class($this->factory);
        Liberator::liberateClass($className)->instance = null;
        $instance = $className::instance();

        $this->assertInstanceOf($className, $instance);
        $this->assertSame($instance, $className::instance());
    }
}
