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
use Eloquent\Lockbox\Transform\Factory\PasswordDecryptTransformFactory;
use PHPUnit_Framework_TestCase;

class RawPasswordDecrypterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->transformFactory = new PasswordDecryptTransformFactory;
        $this->decrypter = new RawPasswordDecrypter($this->transformFactory);
    }

    public function testConstructor()
    {
        $this->assertSame($this->transformFactory, $this->decrypter->transformFactory());
    }

    public function testConstructorDefaults()
    {
        $this->decrypter = new RawPasswordDecrypter;

        $this->assertSame(PasswordDecryptTransformFactory::instance(), $this->decrypter->transformFactory());
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
