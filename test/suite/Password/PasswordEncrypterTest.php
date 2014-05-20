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

use Eloquent\Endec\Base64\Base64Url;
use Eloquent\Liberator\Liberator;
use PHPUnit_Framework_TestCase;

/**
 * @covers \Eloquent\Lockbox\Password\PasswordEncrypter
 * @covers \Eloquent\Lockbox\AbstractEncrypter
 */
class PasswordEncrypterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->rawEncrypter = new RawPasswordEncrypter;
        $this->encoder = new Base64Url;
        $this->encrypter = new PasswordEncrypter($this->rawEncrypter, $this->encoder);
    }

    public function testConstructor()
    {
        $this->assertSame($this->rawEncrypter, $this->encrypter->rawEncrypter());
        $this->assertSame($this->encoder, $this->encrypter->encoder());
    }

    public function testConstructorDefaults()
    {
        $this->encrypter = new PasswordEncrypter;

        $this->assertSame(RawPasswordEncrypter::instance(), $this->encrypter->rawEncrypter());
        $this->assertSame(Base64Url::instance(), $this->encrypter->encoder());
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
