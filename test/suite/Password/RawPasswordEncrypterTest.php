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
use Eloquent\Lockbox\Password\Cipher\Factory\PasswordEncryptCipherFactory;
use PHPUnit_Framework_TestCase;

class RawPasswordEncrypterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->cipherFactory = new PasswordEncryptCipherFactory;
        $this->encrypter = new RawPasswordEncrypter($this->cipherFactory);
    }

    public function testConstructor()
    {
        $this->assertSame($this->cipherFactory, $this->encrypter->cipherFactory());
    }

    public function testConstructorDefaults()
    {
        $this->encrypter = new RawPasswordEncrypter;

        $this->assertSame(PasswordEncryptCipherFactory::instance(), $this->encrypter->cipherFactory());
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
