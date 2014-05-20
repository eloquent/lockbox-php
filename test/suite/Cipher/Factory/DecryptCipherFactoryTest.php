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
use Eloquent\Lockbox\Cipher\DecryptCipher;
use Eloquent\Lockbox\Cipher\Result\Factory\CipherResultFactory;
use Eloquent\Lockbox\Padding\PkcsPadding;
use PHPUnit_Framework_TestCase;

class DecryptCipherFactoryTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->unpadder = new PkcsPadding;
        $this->resultFactory = new CipherResultFactory;
        $this->factory = new DecryptCipherFactory($this->unpadder, $this->resultFactory);
    }

    public function testConstructor()
    {
        $this->assertSame($this->unpadder, $this->factory->unpadder());
        $this->assertSame($this->resultFactory, $this->factory->resultFactory());
    }

    public function testConstructorDefaults()
    {
        $this->factory = new DecryptCipherFactory;

        $this->assertSame(PkcsPadding::instance(), $this->factory->unpadder());
        $this->assertSame(CipherResultFactory::instance(), $this->factory->resultFactory());
    }

    public function testCreateCipher()
    {
        $expected = new DecryptCipher($this->unpadder);
        $actual = $this->factory->createCipher();

        $this->assertEquals($expected, $actual);
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
