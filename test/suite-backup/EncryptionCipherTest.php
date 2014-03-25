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

use PHPUnit_Framework_TestCase;

class EncryptionCipherTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->cipher = new EncryptionCipher(MCRYPT_DEV_RANDOM);
    }

    public function testConstructor()
    {
        $this->assertSame(MCRYPT_DEV_RANDOM, $this->cipher->randomSource());
    }

    public function testConstructorDefaults()
    {
        $this->cipher = new EncryptionCipher;

        $this->assertSame(MCRYPT_DEV_URANDOM, $this->cipher->randomSource());
    }
}
