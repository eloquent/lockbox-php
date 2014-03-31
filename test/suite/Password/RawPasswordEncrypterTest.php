<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Password;

use Eloquent\Liberator\Liberator;
use Eloquent\Lockbox\Transform\Factory\PasswordEncryptTransformFactory;
use PHPUnit_Framework_TestCase;

class RawPasswordEncrypterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->transformFactory = new PasswordEncryptTransformFactory;
        $this->encrypter = new RawPasswordEncrypter($this->transformFactory);
    }

    public function testConstructor()
    {
        $this->assertSame($this->transformFactory, $this->encrypter->transformFactory());
    }

    public function testConstructorDefaults()
    {
        $this->encrypter = new RawPasswordEncrypter;

        $this->assertSame(PasswordEncryptTransformFactory::instance(), $this->encrypter->transformFactory());
    }

    public function testInstance()
    {
        $className = get_class($this->encrypter);
        Liberator::liberateClass($className)->instance = null;
        $instance = $className::instance();

        $this->assertInstanceOf($className, $instance);
        $this->assertSame($instance, $className::instance());
    }
}
