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
use Eloquent\Lockbox\Random\DevUrandom;
use PHPUnit_Framework_TestCase;
use Phake;

class KeyGeneratorTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->factory = new KeyFactory;
        $this->randomSource = Phake::mock('Eloquent\Lockbox\Random\RandomSourceInterface');
        $this->generator = new KeyGenerator($this->factory, $this->randomSource);
    }

    public function testConstructor()
    {
        $this->assertSame($this->factory, $this->generator->factory());
        $this->assertSame($this->randomSource, $this->generator->randomSource());
    }

    public function testConstructorDefaults()
    {
        $this->generator = new KeyGenerator;

        $this->assertSame(KeyFactory::instance(), $this->generator->factory());
        $this->assertSame(DevUrandom::instance(), $this->generator->randomSource());
    }

    public function testGenerateKey()
    {
        Phake::when($this->randomSource)->generate(16)->thenReturn('1234567890123456');
        $key = $this->generator->generateKey(128, 'name', 'description');

        $this->assertSame('1234567890123456', $key->data());
        $this->assertSame('name', $key->name());
        $this->assertSame('description', $key->description());
    }

    public function testGenerateKeyDefaults()
    {
        Phake::when($this->randomSource)->generate(32)->thenReturn('12345678901234567890123456789012');
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
