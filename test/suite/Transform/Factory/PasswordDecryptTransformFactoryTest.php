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
use Eloquent\Lockbox\Password\Cipher\Factory\PasswordDecryptCipherFactory;
use Eloquent\Lockbox\Password\Cipher\PasswordDecryptCipher;
use Eloquent\Lockbox\Transform\PasswordDecryptTransform;
use PHPUnit_Framework_TestCase;

class PasswordDecryptTransformFactoryTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->keyDeriver = new KeyDeriver;
        $this->cipherFactory = new PasswordDecryptCipherFactory($this->keyDeriver);
        $this->factory = new PasswordDecryptTransformFactory($this->cipherFactory);
    }

    public function testConstructor()
    {
        $this->assertSame($this->cipherFactory, $this->factory->cipherFactory());
    }

    public function testConstructorDefaults()
    {
        $this->factory = new PasswordDecryptTransformFactory;

        $this->assertSame(PasswordDecryptCipherFactory::instance(), $this->factory->cipherFactory());
    }

    public function testCreateTransform()
    {
        $this->assertEquals(
            new PasswordDecryptTransform(new PasswordDecryptCipher('password', $this->keyDeriver)),
            $this->factory->createTransform('password')
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
