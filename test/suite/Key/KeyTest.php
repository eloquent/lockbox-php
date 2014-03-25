<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Key;

use PHPUnit_Framework_TestCase;

class KeyTest extends PHPUnit_Framework_TestCase
{
    public function test256BitKey()
    {
        $this->key = new Key('12345678901234567890123456789012', 'name', 'description');

        $this->assertSame('12345678901234567890123456789012', $this->key->data());
        $this->assertSame('name', $this->key->name());
        $this->assertSame('description', $this->key->description());
        $this->assertSame(256, $this->key->size());
        $this->assertSame('MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI', $this->key->string());
        $this->assertSame('MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI', strval($this->key));
    }

    public function test192BitKey()
    {
        $this->key = new Key('123456789012345678901234', 'name', 'description');

        $this->assertSame('123456789012345678901234', $this->key->data());
        $this->assertSame('name', $this->key->name());
        $this->assertSame('description', $this->key->description());
        $this->assertSame(192, $this->key->size());
        $this->assertSame('MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0', $this->key->string());
        $this->assertSame('MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0', strval($this->key));
    }

    public function test128BitKey()
    {
        $this->key = new Key('1234567890123456', 'name', 'description');

        $this->assertSame('1234567890123456', $this->key->data());
        $this->assertSame('name', $this->key->name());
        $this->assertSame('description', $this->key->description());
        $this->assertSame(128, $this->key->size());
        $this->assertSame('MTIzNDU2Nzg5MDEyMzQ1Ng', $this->key->string());
        $this->assertSame('MTIzNDU2Nzg5MDEyMzQ1Ng', strval($this->key));
    }

    public function testNoNameAndDescription()
    {
        $this->key = new Key('1234567890123456');

        $this->assertNull($this->key->name());
        $this->assertNull($this->key->description());
    }

    public function testInvalidKeyData()
    {
        $this->setExpectedException('Eloquent\Lockbox\Key\Exception\InvalidKeyException');
        new Key(null);
    }

    public function testInvalidKeySize()
    {
        $this->setExpectedException('Eloquent\Lockbox\Key\Exception\InvalidKeySizeException');
        new Key('123456789012345678901234567890123');
    }
}
