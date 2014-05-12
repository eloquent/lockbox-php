<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Transform\Factory;

use Eloquent\Liberator\Liberator;
use Eloquent\Lockbox\Key\Key;
use Eloquent\Lockbox\Padding\PkcsPadding;
use Eloquent\Lockbox\Random\DevUrandom;
use PHPUnit_Framework_TestCase;
use Phake;

class EncryptTransformFactoryTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->randomSource = Phake::mock('Eloquent\Lockbox\Random\RandomSourceInterface');
        $this->padder = new PkcsPadding;
        $this->factory = new EncryptTransformFactory($this->randomSource, $this->padder);

        $this->iv = '1234567890123456';
        Phake::when($this->randomSource)->generate(16)->thenReturn($this->iv);
    }

    public function testConstructor()
    {
        $this->assertSame($this->randomSource, $this->factory->randomSource());
        $this->assertSame($this->padder, $this->factory->padder());
    }

    public function testConstructorDefaults()
    {
        $this->factory = new EncryptTransformFactory;

        $this->assertSame(DevUrandom::instance(), $this->factory->randomSource());
        $this->assertSame(PkcsPadding::instance(), $this->factory->padder());
    }

    public function testCreateTransform()
    {
        $key = new Key('1234567890123456', '1234567890123456789012345678');

        $this->assertInstanceOf('Eloquent\Lockbox\Transform\CipherTransform', $this->factory->createTransform($key));
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
