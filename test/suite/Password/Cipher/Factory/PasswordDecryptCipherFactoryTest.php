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
use Eloquent\Lockbox\Key\KeyDeriver;
use Eloquent\Lockbox\Padding\PkcsPadding;
use Eloquent\Lockbox\Password\Cipher\PasswordDecryptCipher;
use Eloquent\Lockbox\Password\Cipher\Result\Factory\PasswordDecryptResultFactory;
use PHPUnit_Framework_TestCase;

class PasswordDecryptCipherFactoryTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->keyDeriver = new KeyDeriver;
        $this->unpadder = new PkcsPadding;
        $this->resultFactory = new PasswordDecryptResultFactory;
        $this->factory = new PasswordDecryptCipherFactory(
            111,
            $this->keyDeriver,
            $this->unpadder,
            $this->resultFactory
        );
    }

    public function testConstructor()
    {
        $this->assertSame(111, $this->factory->maxIterations());
        $this->assertSame($this->keyDeriver, $this->factory->keyDeriver());
        $this->assertSame($this->unpadder, $this->factory->unpadder());
        $this->assertSame($this->resultFactory, $this->factory->resultFactory());
    }

    public function testConstructorDefaults()
    {
        $this->factory = new PasswordDecryptCipherFactory;

        $this->assertSame(4194304, $this->factory->maxIterations());
        $this->assertSame(KeyDeriver::instance(), $this->factory->keyDeriver());
        $this->assertSame(PkcsPadding::instance(), $this->factory->unpadder());
        $this->assertSame(PasswordDecryptResultFactory::instance(), $this->factory->resultFactory());
    }

    public function testCreateCipher()
    {
        $expected = new PasswordDecryptCipher(111, $this->keyDeriver, $this->unpadder);
        $actual = $this->factory->createCipher();

        $this->assertEquals($expected, $actual);
        $this->assertSame(111, $actual->maxIterations());
        $this->assertSame($this->keyDeriver, $actual->keyDeriver());
        $this->assertSame($this->unpadder, $actual->unpadder());
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
