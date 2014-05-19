<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Cipher\Factory;

use Eloquent\Liberator\Liberator;
use Eloquent\Lockbox\Cipher\EncryptCipher;
use Eloquent\Lockbox\Padding\PkcsPadding;
use Eloquent\Lockbox\Random\DevUrandom;
use PHPUnit_Framework_TestCase;

class EncryptCipherFactoryTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->randomSource = new DevUrandom;
        $this->padder = new PkcsPadding;
        $this->factory = new EncryptCipherFactory($this->randomSource, $this->padder);
    }

    public function testConstructor()
    {
        $this->assertSame($this->randomSource, $this->factory->randomSource());
        $this->assertSame($this->padder, $this->factory->padder());
    }

    public function testConstructorDefaults()
    {
        $this->factory = new EncryptCipherFactory;

        $this->assertSame(DevUrandom::instance(), $this->factory->randomSource());
        $this->assertSame(PkcsPadding::instance(), $this->factory->padder());
    }

    public function testCreateCipher()
    {
        $expected = new EncryptCipher($this->randomSource, $this->padder);
        $actual = $this->factory->createCipher();

        $this->assertEquals($expected, $actual);
        $this->assertSame($this->randomSource, $actual->randomSource());
        $this->assertSame($this->padder, $actual->padder());
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
