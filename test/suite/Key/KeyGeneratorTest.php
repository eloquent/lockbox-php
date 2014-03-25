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
use Icecave\Isolator\Isolator;
use Phake;
use PHPUnit_Framework_TestCase;

class KeyGeneratorTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->factory = new KeyFactory;
        $this->isolator = Phake::mock(Isolator::className());
        $this->generator = new KeyGenerator($this->factory, MCRYPT_DEV_RANDOM, $this->isolator);
    }

    public function testConstructor()
    {
        $this->assertSame($this->factory, $this->generator->factory());
        $this->assertSame(MCRYPT_DEV_RANDOM, $this->generator->randomSource());
    }

    public function testConstructorDefaults()
    {
        $this->generator = new KeyGenerator;

        $this->assertSame(KeyFactory::instance(), $this->generator->factory());
        $this->assertSame(MCRYPT_DEV_URANDOM, $this->generator->randomSource());
    }

    public function testGenerateKey()
    {
        Phake::when($this->isolator)->mcrypt_create_iv(16, MCRYPT_DEV_RANDOM)->thenReturn('1234567890123456');
        $key = $this->generator->generateKey(128, 'name', 'description');

        $this->assertSame('1234567890123456', $key->data());
        $this->assertSame('name', $key->name());
        $this->assertSame('description', $key->description());
    }

    public function testGenerateKeyDefaults()
    {
        Phake::when($this->isolator)->mcrypt_create_iv(32, MCRYPT_DEV_RANDOM)->thenReturn('12345678901234567890123456789012');
        $key = $this->generator->generateKey();

        $this->assertSame('12345678901234567890123456789012', $key->data());
        $this->assertNull($key->name());
        $this->assertNull($key->description());
    }

    public function testGenerateKeyFailureInvalidSize()
    {
        $this->setExpectedException('Eloquent\Lockbox\Key\Exception\InvalidKeySizeException');
        $this->generator->generateKey(257);
    }

    public function testInstance()
    {
        $className = get_class($this->generator);
        Liberator::liberateClass($className)->instance = null;
        $instance = $className::instance();

        $this->assertInstanceOf($className, $instance);
        $this->assertSame($instance, $className::instance());
    }
}
