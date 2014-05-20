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

use Eloquent\Liberator\Liberator;
use Eloquent\Lockbox\Password\Cipher\Factory\PasswordDecryptCipherFactory;
use PHPUnit_Framework_TestCase;

/**
 * @covers \Eloquent\Lockbox\Password\RawPasswordDecrypter
 * @covers \Eloquent\Lockbox\AbstractRawDecrypter
 */
class RawPasswordDecrypterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->cipherFactory = new PasswordDecryptCipherFactory;
        $this->decrypter = new RawPasswordDecrypter($this->cipherFactory);
    }

    public function testConstructor()
    {
        $this->assertSame($this->cipherFactory, $this->decrypter->cipherFactory());
    }

    public function testConstructorDefaults()
    {
        $this->decrypter = new RawPasswordDecrypter;

        $this->assertSame(PasswordDecryptCipherFactory::instance(), $this->decrypter->cipherFactory());
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
