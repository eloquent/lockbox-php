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

use Eloquent\Endec\Base64\Base64Url;
use Eloquent\Liberator\Liberator;
use Eloquent\Lockbox\Random\DevUrandom;
use Phake;
use PHPUnit_Framework_TestCase;

class EncrypterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->base64UrlEncoder = new Base64Url;
        $this->randomSource = Phake::mock('Eloquent\Lockbox\Random\RandomSourceInterface');
        $this->encrypter = new Encrypter($this->randomSource, $this->base64UrlEncoder);
    }

    public function testConstructor()
    {
        $this->assertSame($this->randomSource, $this->encrypter->randomSource());
        $this->assertSame($this->base64UrlEncoder, $this->encrypter->base64UrlEncoder());
    }

    public function testConstructorDefaults()
    {
        $this->encrypter = new Encrypter;

        $this->assertSame(DevUrandom::instance(), $this->encrypter->randomSource());
        $this->assertSame(Base64Url::instance(), $this->encrypter->base64UrlEncoder());
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
