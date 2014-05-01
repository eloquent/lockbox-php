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
use Eloquent\Lockbox\Cipher\EncryptCipher;
use Eloquent\Lockbox\Cipher\Factory\EncryptCipherFactory;
use Eloquent\Lockbox\Key\Key;
use Eloquent\Lockbox\Transform\EncryptTransform;
use PHPUnit_Framework_TestCase;
use Phake;

class EncryptTransformFactoryTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->randomSource = Phake::mock('Eloquent\Lockbox\Random\RandomSourceInterface');
        $this->cipherFactory = new EncryptCipherFactory($this->randomSource);
        $this->factory = new EncryptTransformFactory($this->cipherFactory);

        $this->iv = '1234567890123456';
        Phake::when($this->randomSource)->generate(16)->thenReturn($this->iv);
    }

    public function testConstructor()
    {
        $this->assertSame($this->cipherFactory, $this->factory->cipherFactory());
    }

    public function testConstructorDefaults()
    {
        $this->factory = new EncryptTransformFactory;

        $this->assertSame(EncryptCipherFactory::instance(), $this->factory->cipherFactory());
    }

    public function testCreateTransform()
    {
        $key = new Key('1234567890123456', '1234567890123456789012345678');

        $this->assertEquals(
            new EncryptTransform(new EncryptCipher($key, $this->iv)),
            $this->factory->createTransform($key)
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
