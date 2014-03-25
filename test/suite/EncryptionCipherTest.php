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

class EncryptionCipherTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->base64UrlEncoder = new Base64Url;
        $this->cipher = new EncryptionCipher(MCRYPT_DEV_RANDOM, $this->base64UrlEncoder);
    }

    public function testConstructor()
    {
        $this->assertSame(MCRYPT_DEV_RANDOM, $this->cipher->randomSource());
        $this->assertSame($this->base64UrlEncoder, $this->cipher->base64UrlEncoder());
    }

    public function testConstructorDefaults()
    {
        $this->cipher = new EncryptionCipher;

        $this->assertSame(MCRYPT_DEV_URANDOM, $this->cipher->randomSource());
        $this->assertSame(Base64Url::instance(), $this->cipher->base64UrlEncoder());
    }

    public function testInstance()
    {
        $className = get_class($this->cipher);
        Liberator::liberateClass($className)->instance = null;
        $instance = $className::instance();

        $this->assertInstanceOf($className, $instance);
        $this->assertSame($instance, $className::instance());
    }
}
