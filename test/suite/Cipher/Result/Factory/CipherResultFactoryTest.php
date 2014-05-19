<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Cipher\Result\Factory;

use Eloquent\Liberator\Liberator;
use Eloquent\Lockbox\Cipher\Result\CipherResult;
use Eloquent\Lockbox\Cipher\Result\CipherResultType;
use PHPUnit_Framework_TestCase;

class CipherResultFactoryTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->factory = new CipherResultFactory;
    }

    public function testCreateCipher()
    {
        $expected = new CipherResult(CipherResultType::SUCCESS(), 'foo');
        $actual = $this->factory->createResult(CipherResultType::SUCCESS(), 'foo');

        $this->assertEquals($expected, $actual);
        $this->assertSame(CipherResultType::SUCCESS(), $actual->type());
        $this->assertSame('foo', $actual->data());
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
