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

use Eloquent\Endec\Base64\Base64UrlEncodeTransform;
use Eloquent\Liberator\Liberator;
use Eloquent\Lockbox\Transform\Factory\EncryptTransformFactory;
use PHPUnit_Framework_TestCase;

class EncrypterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->transformFactory = new EncryptTransformFactory;
        $this->encodeTransform = new Base64UrlEncodeTransform;
        $this->encrypter = new Encrypter($this->transformFactory, $this->encodeTransform);
    }

    public function testConstructor()
    {
        $this->assertSame($this->transformFactory, $this->encrypter->transformFactory());
        $this->assertSame($this->encodeTransform, $this->encrypter->encodeTransform());
    }

    public function testConstructorDefaults()
    {
        $this->encrypter = new Encrypter;

        $this->assertSame(EncryptTransformFactory::instance(), $this->encrypter->transformFactory());
        $this->assertSame(Base64UrlEncodeTransform::instance(), $this->encrypter->encodeTransform());
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
