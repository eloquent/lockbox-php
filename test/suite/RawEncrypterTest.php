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
use Eloquent\Lockbox\Cipher\Factory\EncryptCipherFactory;
use PHPUnit_Framework_TestCase;

/**
 * @covers \Eloquent\Lockbox\RawEncrypter
 * @covers \Eloquent\Lockbox\AbstractRawEncrypter
 */
class RawEncrypterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->cipherFactory = new EncryptCipherFactory;
        $this->encrypter = new RawEncrypter($this->cipherFactory);
    }

    public function testConstructor()
    {
        $this->assertSame($this->cipherFactory, $this->encrypter->cipherFactory());
    }

    public function testConstructorDefaults()
    {
        $this->encrypter = new RawEncrypter;

        $this->assertSame(EncryptCipherFactory::instance(), $this->encrypter->cipherFactory());
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
