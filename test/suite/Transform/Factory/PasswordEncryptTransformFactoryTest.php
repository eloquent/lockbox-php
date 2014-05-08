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
use Eloquent\Lockbox\Key\KeyDeriver;
use Eloquent\Lockbox\Padding\PkcsPadding;
use Eloquent\Lockbox\Random\DevUrandom;
use Eloquent\Lockbox\Transform\PasswordEncryptTransform;
use PHPUnit_Framework_TestCase;
use Phake;

class PasswordEncryptTransformFactoryTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->keyDeriver = new KeyDeriver;
        $this->randomSource = Phake::mock('Eloquent\Lockbox\Random\RandomSourceInterface');
        $this->padder = new PkcsPadding;
        $this->factory = new PasswordEncryptTransformFactory($this->keyDeriver, $this->randomSource, $this->padder);

        $this->iv = '1234567890123456';
        $this->salt = '1234567890123456789012345678901234567890123456789012345678901234';

        Phake::when($this->randomSource)->generate(16)->thenReturn($this->iv);
        Phake::when($this->randomSource)->generate(64)->thenReturn($this->salt);
    }

    public function testConstructor()
    {
        $this->assertSame($this->keyDeriver, $this->factory->keyDeriver());
        $this->assertSame($this->randomSource, $this->factory->randomSource());
        $this->assertSame($this->padder, $this->factory->padder());
    }

    public function testConstructorDefaults()
    {
        $this->factory = new PasswordEncryptTransformFactory;

        $this->assertSame(KeyDeriver::instance(), $this->factory->keyDeriver());
        $this->assertSame(DevUrandom::instance(), $this->factory->randomSource());
        $this->assertSame(PkcsPadding::instance(), $this->factory->padder());
    }

    public function testCreateTransform()
    {
        $this->assertInstanceOf(
            'Eloquent\Lockbox\Transform\PasswordEncryptTransform',
            $this->factory->createTransform('password', 111)
        );
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
