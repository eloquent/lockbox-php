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
use Eloquent\Lockbox\Padding\PkcsPadding;
use PHPUnit_Framework_TestCase;

class DecryptCipherFactoryTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->unpadder = new PkcsPadding;
        $this->factory = new DecryptCipherFactory($this->unpadder);
    }

    public function testConstructor()
    {
        $this->assertSame($this->unpadder, $this->factory->unpadder());
    }

    public function testConstructorDefaults()
    {
        $this->factory = new DecryptCipherFactory;

        $this->assertSame(PkcsPadding::instance(), $this->factory->unpadder());
    }

    public function testCreateCipher()
    {
        $expected = new DecryptCipher($this->unpadder);
        $actual = $this->factory->createCipher();

        $this->assertEquals($expected, $actual);
        $this->assertSame($this->unpadder, $actual->unpadder());
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
