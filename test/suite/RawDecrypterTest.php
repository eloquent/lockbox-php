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
use Eloquent\Lockbox\Transform\Factory\DecryptTransformFactory;
use PHPUnit_Framework_TestCase;

class RawDecrypterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->transformFactory = new DecryptTransformFactory;
        $this->decrypter = new RawDecrypter($this->transformFactory);
    }

    public function testConstructor()
    {
        $this->assertSame($this->transformFactory, $this->decrypter->transformFactory());
    }

    public function testConstructorDefaults()
    {
        $this->decrypter = new RawDecrypter;

        $this->assertSame(DecryptTransformFactory::instance(), $this->decrypter->transformFactory());
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
