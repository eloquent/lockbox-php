<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Transform\Factory;

use Eloquent\Liberator\Liberator;
use Eloquent\Lockbox\Key\KeyDeriver;
use Eloquent\Lockbox\Padding\PkcsPadding;
use Eloquent\Lockbox\Transform\PasswordDecryptTransform;
use PHPUnit_Framework_TestCase;

class PasswordDecryptTransformFactoryTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->keyDeriver = new KeyDeriver;
        $this->unpadder = new PkcsPadding;
        $this->factory = new PasswordDecryptTransformFactory($this->keyDeriver, $this->unpadder);
    }

    public function testConstructor()
    {
        $this->assertSame($this->keyDeriver, $this->factory->keyDeriver());
        $this->assertSame($this->unpadder, $this->factory->unpadder());
    }

    public function testConstructorDefaults()
    {
        $this->factory = new PasswordDecryptTransformFactory;

        $this->assertSame(KeyDeriver::instance(), $this->factory->keyDeriver());
        $this->assertSame(PkcsPadding::instance(), $this->factory->unpadder());
    }

    public function testCreateTransform()
    {
        $this->assertInstanceOf(
            'Eloquent\Lockbox\Transform\PasswordDecryptTransform',
            $this->factory->createTransform('password')
        );
    }

    public function testInstance()
    {
        $className = get_class($this->factory);
        Liberator::liberateClass($className)->instance = null;
        $instance = $className::instance();

        $this->assertInstanceOf($className, $instance);
        $this->assertSame($instance, $className::instance());
    }
}
