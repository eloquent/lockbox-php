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
use Eloquent\Lockbox\Random\DevUrandom;
use Eloquent\Lockbox\Transform\PasswordEncryptTransform;
use PHPUnit_Framework_TestCase;

class PasswordEncryptTransformFactoryTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->keyDeriver = new KeyDeriver;
        $this->randomSource = new DevUrandom;
        $this->factory = new PasswordEncryptTransformFactory($this->keyDeriver, $this->randomSource);
    }

    public function testConstructor()
    {
        $this->assertSame($this->keyDeriver, $this->factory->keyDeriver());
        $this->assertSame($this->randomSource, $this->factory->randomSource());
    }

    public function testConstructorDefaults()
    {
        $this->factory = new PasswordEncryptTransformFactory;

        $this->assertSame(KeyDeriver::instance(), $this->factory->keyDeriver());
        $this->assertSame(DevUrandom::instance(), $this->factory->randomSource());
    }

    public function testCreateTransform()
    {
        $this->assertEquals(
            new PasswordEncryptTransform('password', 111, $this->keyDeriver, $this->randomSource),
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
