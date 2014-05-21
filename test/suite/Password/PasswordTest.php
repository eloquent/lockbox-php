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

use PHPUnit_Framework_TestCase;

class PasswordTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->password = new Password('password');
    }

    public function testConstructor()
    {
        $this->assertSame('password', $this->password->string());
        $this->assertSame('password', strval($this->password));
    }

    public function testConstructorFailureNonString()
    {
        $this->setExpectedException('Eloquent\Lockbox\Password\Exception\InvalidPasswordException');
        new Password(null);
    }

    public function testAdapt()
    {
        $this->assertSame($this->password, Password::adapt($this->password));
        $this->assertEquals(new Password('password'), Password::adapt('password'));
    }

    public function testErase()
    {
        $this->password->erase();

        $this->assertSame('', $this->password->string());
    }
}
