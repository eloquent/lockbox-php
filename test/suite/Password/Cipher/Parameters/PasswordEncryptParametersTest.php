<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Password\Cipher\Parameters;

use Eloquent\Lockbox\Password\Password;
use PHPUnit_Framework_TestCase;

class PasswordEncryptParametersTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->password = new Password('password');
        $this->salt = '1234567890123456789012345678901234567890123456789012345678901234';
        $this->iv = '1234567890123456';
        $this->parameters = new PasswordEncryptParameters($this->password, 111, $this->salt, $this->iv);
    }

    public function testConstructor()
    {
        $this->assertSame($this->password, $this->parameters->password());
        $this->assertSame(111, $this->parameters->iterations());
        $this->assertSame($this->salt, $this->parameters->salt());
        $this->assertSame($this->iv, $this->parameters->iv());
    }

    public function testConstructorDefaults()
    {
        $this->parameters = new PasswordEncryptParameters($this->password, 111);

        $this->assertNull($this->parameters->salt());
        $this->assertNull($this->parameters->iv());
    }

    public function testErase()
    {
        $this->parameters->erase();

        $this->assertSame('', $this->parameters->password()->string());
        $this->assertSame(1, $this->parameters->iterations());
        $this->assertNull($this->parameters->salt());
        $this->assertNull($this->parameters->iv());
    }
}
