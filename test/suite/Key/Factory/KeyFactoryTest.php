<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Key\Factory;

use Eloquent\Liberator\Liberator;
use PHPUnit_Framework_TestCase;

class KeyFactoryTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->factory = new KeyFactory;
    }

    public function validSecretData()
    {
        //                              encryptSecret                       authSecret
        return array(
            '256 bit, 512 bit' => array('12345678901234567890123456789012', '1234567890123456789012345678901234567890123456789012345678901234'),
            '256 bit, 384 bit' => array('12345678901234567890123456789012', '123456789012345678901234567890123456789012345678'),
            '256 bit, 256 bit' => array('12345678901234567890123456789012', '12345678901234567890123456789012'),
            '256 bit, 224 bit' => array('12345678901234567890123456789012', '1234567890123456789012345678'),
            '192 bit, 512 bit' => array('123456789012345678901234',         '1234567890123456789012345678901234567890123456789012345678901234'),
            '192 bit, 384 bit' => array('123456789012345678901234',         '123456789012345678901234567890123456789012345678'),
            '192 bit, 256 bit' => array('123456789012345678901234',         '12345678901234567890123456789012'),
            '192 bit, 224 bit' => array('123456789012345678901234',         '1234567890123456789012345678'),
            '128 bit, 512 bit' => array('1234567890123456',                 '1234567890123456789012345678901234567890123456789012345678901234'),
            '128 bit, 384 bit' => array('1234567890123456',                 '123456789012345678901234567890123456789012345678'),
            '128 bit, 256 bit' => array('1234567890123456',                 '12345678901234567890123456789012'),
            '128 bit, 224 bit' => array('1234567890123456',                 '1234567890123456789012345678'),
        );
    }

    /**
     * @dataProvider validSecretData
     */
    public function testCreateKey($encryptSecret, $authSecret)
    {
        $this->key = $this->factory->createKey($encryptSecret, $authSecret, 'name', 'description');

        $this->assertSame($encryptSecret, $this->key->encryptSecret());
        $this->assertSame($authSecret, $this->key->authSecret());
        $this->assertSame('name', $this->key->name());
        $this->assertSame('description', $this->key->description());
    }

    public function testCreateKeyNoNameAndDescription()
    {
        $this->key = $this->factory->createKey('1234567890123456', '12345678901234567890123456789012');

        $this->assertNull($this->key->name());
        $this->assertNull($this->key->description());
    }

    public function testCreateKeyInvalidEncryptSecretSize()
    {
        $this->setExpectedException('Eloquent\Lockbox\Key\Exception\InvalidEncryptSecretSizeException');
        $this->factory->createKey('123456789012345678901234567890123', '12345678901234567890123456789012');
    }

    public function testCreateKeyInvalidAuthSecretSize()
    {
        $this->setExpectedException('Eloquent\Lockbox\Key\Exception\InvalidAuthSecretSizeException');
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
