<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Transform;

use Eloquent\Lockbox\BoundDecrypter;
use Eloquent\Lockbox\Encrypter;
use Eloquent\Lockbox\Key\Key;
use PHPUnit_Framework_TestCase;

class DecryptTransformTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->key = new Key('1234567890123456', '1234567890123456789012345678');
        $this->transform = new DecryptTransform($this->key);

        $this->encrypter = new BoundDecrypter($this->key);
    }

    public function testConstructor()
    {
        $this->assertSame($this->key, $this->transform->key());
    }

}
