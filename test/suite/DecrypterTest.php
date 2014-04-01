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

use Eloquent\Endec\Base64\Base64UrlDecodeTransform;
use Eloquent\Liberator\Liberator;
use Eloquent\Lockbox\Transform\Factory\DecryptTransformFactory;
use PHPUnit_Framework_TestCase;

class DecrypterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->transformFactory = new DecryptTransformFactory;
        $this->decodeTransform = new Base64UrlDecodeTransform;
        $this->decrypter = new Decrypter($this->transformFactory, $this->decodeTransform);
    }

    public function testConstructor()
    {
        $this->assertSame($this->transformFactory, $this->decrypter->transformFactory());
        $this->assertSame($this->decodeTransform, $this->decrypter->decodeTransform());
    }

    public function testConstructorDefaults()
    {
        $this->decrypter = new Decrypter;

        $this->assertSame(DecryptTransformFactory::instance(), $this->decrypter->transformFactory());
        $this->assertSame(Base64UrlDecodeTransform::instance(), $this->decrypter->decodeTransform());
    }

    public function testInstance()
    {
        $className = get_class($this->decrypter);
        Liberator::liberateClass($className)->instance = null;
        $instance = $className::instance();

        $this->assertInstanceOf($className, $instance);
        $this->assertSame($instance, $className::instance());
    }
}
