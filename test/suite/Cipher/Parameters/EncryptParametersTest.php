<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Cipher\Parameters;

use Eloquent\Lockbox\Key\Key;
use PHPUnit_Framework_TestCase;

class EncryptParametersTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->key = new Key('1234567890123456', '1234567890123456789012345678');;
        $this->iv = '1234567890123456';
        $this->parameters = new EncryptParameters($this->key, $this->iv);
    }

    public function testConstructor()
    {
        $this->assertSame($this->key, $this->parameters->key());
        $this->assertSame($this->iv, $this->parameters->iv());
    }

    public function testConstructorDefaults()
    {
        $this->parameters = new EncryptParameters($this->key);

        $this->assertNull($this->parameters->iv());
    }
}
