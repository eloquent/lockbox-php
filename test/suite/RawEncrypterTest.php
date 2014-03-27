<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox;

use Eloquent\Liberator\Liberator;
use Eloquent\Lockbox\Random\DevUrandom;
use Phake;
use PHPUnit_Framework_TestCase;

class RawEncrypterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->randomSource = Phake::mock('Eloquent\Lockbox\Random\RandomSourceInterface');
        $this->encrypter = new RawEncrypter($this->randomSource);
    }

    public function testConstructor()
    {
        $this->assertSame($this->randomSource, $this->encrypter->randomSource());
    }

    public function testConstructorDefaults()
    {
        $this->encrypter = new RawEncrypter;

        $this->assertSame(DevUrandom::instance(), $this->encrypter->randomSource());
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
