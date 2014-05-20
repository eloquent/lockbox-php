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
use Eloquent\Lockbox\Cipher\Factory\DecryptCipherFactory;
use PHPUnit_Framework_TestCase;

/**
 * @covers \Eloquent\Lockbox\RawDecrypter
 * @covers \Eloquent\Lockbox\AbstractRawDecrypter
 */
class RawDecrypterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->cipherFactory = new DecryptCipherFactory;
        $this->decrypter = new RawDecrypter($this->cipherFactory);
    }

    public function testConstructor()
    {
        $this->assertSame($this->cipherFactory, $this->decrypter->cipherFactory());
    }

    public function testConstructorDefaults()
    {
        $this->decrypter = new RawDecrypter;

        $this->assertSame(DecryptCipherFactory::instance(), $this->decrypter->cipherFactory());
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
