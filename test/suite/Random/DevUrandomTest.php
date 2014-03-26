<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Random;

use Eloquent\Liberator\Liberator;
use Icecave\Isolator\Isolator;
use PHPUnit_Framework_TestCase;
use Phake;

/**
 * @covers \Eloquent\Lockbox\Random\DevUrandom
 * @covers \Eloquent\Lockbox\Random\AbstractMcryptRandomSource
 */
class DevUrandomTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->isolator = Phake::mock(Isolator::className());
        $this->source = new DevUrandom($this->isolator);
    }

    public function testGenerate()
    {
        Phake::when($this->isolator)->mcrypt_create_iv(111, MCRYPT_DEV_URANDOM)->thenReturn('foo');

        $this->assertSame('foo', $this->source->generate(111));
    }

    public function testInstance()
    {
        $className = get_class($this->source);
        Liberator::liberateClass($className)->instance = null;
        $instance = $className::instance();

        $this->assertInstanceOf($className, $instance);
        $this->assertSame($instance, $className::instance());
    }
}
