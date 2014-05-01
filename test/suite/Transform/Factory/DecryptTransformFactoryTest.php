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
use Eloquent\Lockbox\Cipher\DecryptCipher;
use Eloquent\Lockbox\Cipher\Factory\DecryptCipherFactory;
use Eloquent\Lockbox\Key\Key;
use Eloquent\Lockbox\Transform\DecryptTransform;
use PHPUnit_Framework_TestCase;

class DecryptTransformFactoryTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->cipherFactory = new DecryptCipherFactory;
        $this->factory = new DecryptTransformFactory($this->cipherFactory);
    }

    public function testConstructor()
    {
        $this->assertSame($this->cipherFactory, $this->factory->cipherFactory());
    }

    public function testConstructorDefaults()
    {
        $this->factory = new DecryptTransformFactory;

        $this->assertSame(DecryptCipherFactory::instance(), $this->factory->cipherFactory());
    }

    public function testCreateTransform()
    {
        $key = new Key('1234567890123456', '1234567890123456789012345678');

        $this->assertEquals(new DecryptTransform(new DecryptCipher($key)), $this->factory->createTransform($key));
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
