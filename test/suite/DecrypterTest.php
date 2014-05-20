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
use PHPUnit_Framework_TestCase;

/**
 * @covers \Eloquent\Lockbox\Decrypter
 * @covers \Eloquent\Lockbox\AbstractDecrypter
 */
class DecrypterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->rawDecrypter = new RawDecrypter;
        $this->decoder = new Base64Url;
        $this->decrypter = new Decrypter($this->rawDecrypter, $this->decoder);
    }

    public function testConstructor()
    {
        $this->assertSame($this->rawDecrypter, $this->decrypter->rawDecrypter());
        $this->assertSame($this->decoder, $this->decrypter->decoder());
    }

    public function testConstructorDefaults()
    {
        $this->decrypter = new Decrypter;

        $this->assertSame(RawDecrypter::instance(), $this->decrypter->rawDecrypter());
        $this->assertSame(Base64Url::instance(), $this->decrypter->decoder());
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
