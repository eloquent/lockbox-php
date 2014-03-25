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

    public function testCreateKey256BitKey()
    {
        $this->key = $this->factory->createKey('12345678901234567890123456789012', 'name', 'description');

        $this->assertSame('12345678901234567890123456789012', $this->key->data());
        $this->assertSame('name', $this->key->name());
        $this->assertSame('description', $this->key->description());
    }

    public function testCreateKey192BitKey()
    {
        $this->key = $this->factory->createKey('123456789012345678901234', 'name', 'description');

        $this->assertSame('123456789012345678901234', $this->key->data());
        $this->assertSame('name', $this->key->name());
        $this->assertSame('description', $this->key->description());
    }

    public function testCreateKey128BitKey()
    {
        $this->key = $this->factory->createKey('1234567890123456', 'name', 'description');

        $this->assertSame('1234567890123456', $this->key->data());
        $this->assertSame('name', $this->key->name());
        $this->assertSame('description', $this->key->description());
    }

    public function testCreateKeyNoNameAndDescription()
    {
        $this->key = $this->factory->createKey('1234567890123456');

        $this->assertNull($this->key->name());
        $this->assertNull($this->key->description());
    }

    public function testCreateKeyInvalidKeySize()
    {
        $this->setExpectedException('Eloquent\Lockbox\Key\Exception\InvalidKeySizeException');
        $this->factory->createKey('123456789012345678901234567890123');
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
