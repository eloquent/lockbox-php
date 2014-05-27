<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Key\Generator;

use Eloquent\Liberator\Liberator;
use Eloquent\Lockbox\Key\Factory\KeyFactory;
use Eloquent\Lockbox\Random\DevUrandom;
use PHPUnit_Framework_TestCase;
use Phake;

class KeyGeneratorTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->randomSource = Phake::mock('Eloquent\Lockbox\Random\RandomSourceInterface');
        $this->factory = new KeyFactory;
        $this->generator = new KeyGenerator($this->randomSource, $this->factory);
    }

    public function testConstructor()
    {
        $this->assertSame($this->randomSource, $this->generator->randomSource());
        $this->assertSame($this->factory, $this->generator->factory());
    }

    public function testConstructorDefaults()
    {
        $this->generator = new KeyGenerator;

        $this->assertSame(DevUrandom::instance(), $this->generator->randomSource());
        $this->assertSame(KeyFactory::instance(), $this->generator->factory());
    }

    public function testGenerateKey()
    {
        Phake::when($this->randomSource)->generate(16)->thenReturn('1234567890123456');
        Phake::when($this->randomSource)->generate(28)->thenReturn('1234567890123456789012345678');
        $key = $this->generator->generateKey('name', 'description', 128, 224);

        $this->assertSame('1234567890123456', $key->encryptSecret());
        $this->assertSame('1234567890123456789012345678', $key->authSecret());
        $this->assertSame('name', $key->name());
        $this->assertSame('description', $key->description());
    }

    public function testGenerateKeyDefaults()
    {
        Phake::when($this->randomSource)->generate(32)
            ->thenReturn('12345678901234567890123456789012')
            ->thenReturn('12345678901234567890123456789013');
        $key = $this->generator->generateKey();

        $this->assertSame('12345678901234567890123456789012', $key->encryptSecret());
        $this->assertSame('12345678901234567890123456789013', $key->authSecret());
        $this->assertNull($key->name());
        $this->assertNull($key->description());
    }

    public function testGenerateKeyFailureInvalidEncryptSecretSize()
    {
        $this->setExpectedException('Eloquent\Lockbox\Key\Exception\InvalidEncryptSecretSizeException');
        $this->generator->generateKey(null, null, 257);
    }

    public function testGenerateKeyFailureInvalidAuthSecretSize()
    {
        $this->setExpectedException('Eloquent\Lockbox\Key\Exception\InvalidAuthSecretSizeException');
        $this->generator->generateKey(null, null, null, 513);
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
