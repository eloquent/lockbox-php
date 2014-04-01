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

use Eloquent\Endec\Base64\Base64UrlDecodeTransform;
use Eloquent\Liberator\Liberator;
use Eloquent\Lockbox\Transform\Factory\PasswordDecryptTransformFactory;
use PHPUnit_Framework_TestCase;

class PasswordDecrypterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->transformFactory = new PasswordDecryptTransformFactory;
        $this->decodeTransform = new Base64UrlDecodeTransform;
        $this->encrypter = new PasswordDecrypter($this->transformFactory, $this->decodeTransform);
    }

    public function testConstructor()
    {
        $this->assertSame($this->transformFactory, $this->encrypter->transformFactory());
        $this->assertSame($this->decodeTransform, $this->encrypter->decodeTransform());
    }

    public function testConstructorDefaults()
    {
        $this->encrypter = new PasswordDecrypter;

        $this->assertSame(PasswordDecryptTransformFactory::instance(), $this->encrypter->transformFactory());
        $this->assertSame(Base64UrlDecodeTransform::instance(), $this->encrypter->decodeTransform());
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
