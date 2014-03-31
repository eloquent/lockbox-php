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

class PasswordDecrypterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->rawDecrypter = new RawPasswordDecrypter;
        $this->decoder = new Base64Url;
        $this->encrypter = new PasswordDecrypter($this->rawDecrypter, $this->decoder);
    }

    public function testConstructor()
    {
        $this->assertSame($this->rawDecrypter, $this->encrypter->rawDecrypter());
        $this->assertSame($this->decoder, $this->encrypter->decoder());
    }

    public function testConstructorDefaults()
    {
        $this->encrypter = new PasswordDecrypter;

        $this->assertSame(RawPasswordDecrypter::instance(), $this->encrypter->rawDecrypter());
        $this->assertSame(Base64Url::instance(), $this->encrypter->decoder());
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
