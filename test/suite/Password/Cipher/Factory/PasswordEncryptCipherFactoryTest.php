<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Password\Cipher\Factory;

use Eloquent\Liberator\Liberator;
use Eloquent\Lockbox\Cipher\Result\Factory\CipherResultFactory;
use Eloquent\Lockbox\Key\KeyDeriver;
use Eloquent\Lockbox\Padding\PkcsPadding;
use Eloquent\Lockbox\Password\Cipher\PasswordEncryptCipher;
use Eloquent\Lockbox\Random\DevUrandom;
use PHPUnit_Framework_TestCase;

class PasswordEncryptCipherFactoryTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->randomSource = new DevUrandom;
        $this->keyDeriver = new KeyDeriver;
        $this->padder = new PkcsPadding;
        $this->resultFactory = new CipherResultFactory;
        $this->factory = new PasswordEncryptCipherFactory(
            $this->randomSource,
            $this->keyDeriver,
            $this->padder,
            $this->resultFactory
        );
    }

    public function testConstructor()
    {
        $this->assertSame($this->randomSource, $this->factory->randomSource());
        $this->assertSame($this->keyDeriver, $this->factory->keyDeriver());
        $this->assertSame($this->padder, $this->factory->padder());
        $this->assertSame($this->resultFactory, $this->factory->resultFactory());
    }

    public function testConstructorDefaults()
    {
        $this->factory = new PasswordEncryptCipherFactory;

        $this->assertSame(DevUrandom::instance(), $this->factory->randomSource());
        $this->assertSame(KeyDeriver::instance(), $this->factory->keyDeriver());
        $this->assertSame(PkcsPadding::instance(), $this->factory->padder());
        $this->assertSame(CipherResultFactory::instance(), $this->factory->resultFactory());
    }

    public function testCreateCipher()
    {
        $expected = new PasswordEncryptCipher($this->randomSource, $this->keyDeriver, $this->padder);
        $actual = $this->factory->createCipher();

        $this->assertEquals($expected, $actual);
        $this->assertSame($this->randomSource, $actual->randomSource());
        $this->assertSame($this->keyDeriver, $actual->keyDeriver());
        $this->assertSame($this->padder, $actual->padder());
        $this->assertSame($this->resultFactory, $actual->resultFactory());
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
