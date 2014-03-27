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

use Eloquent\Lockbox\BoundEncrypter;
use Eloquent\Lockbox\Encrypter;
use Eloquent\Lockbox\Key\Key;
use Eloquent\Lockbox\Random\DevUrandom;
use Eloquent\Lockbox\RawEncrypter;
use PHPUnit_Framework_TestCase;
use Phake;

class EncryptTransformTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->key = new Key('1234567890123456', '1234567890123456789012345678');
        $this->randomSource = Phake::mock('Eloquent\Lockbox\Random\RandomSourceInterface');
        $this->transform = new EncryptTransform($this->key, $this->randomSource);

        $this->encrypter = new BoundEncrypter($this->key, new RawEncrypter($this->randomSource));

        Phake::when($this->randomSource)->generate(16)->thenReturn('1234567890123456');
    }

    public function testConstructor()
    {
        $this->assertSame($this->key, $this->transform->key());
        $this->assertSame($this->randomSource, $this->transform->randomSource());
    }

    public function testConstructorDefaults()
    {
        $this->transform = new EncryptTransform($this->key);

        $this->assertSame(DevUrandom::instance(), $this->transform->randomSource());
    }

    public function testTransform()
    {
        $encrypted = '';
        $buffer = '';
        foreach (array('foo', 'bar', 'baz', 'qux', 'dooms', 'plat') as $data) {
            $buffer .= $data;
            list($output, $consumed) = $this->transform->transform($buffer, $context);
            $encrypted .= $output;
            if (strlen($buffer) === $consumed) {
                $buffer = '';
            } else {
                $buffer = substr($buffer, $consumed);
            }
        }
        list($output, $consumed) = $this->transform->transform($buffer, $context, true);
        $encrypted .= $output;

        $this->assertSameCiphertext($this->encrypter->encrypt('foobarbazquxdoomsplat'), $encrypted);
        $this->assertNull($context);
    }

    public function testTransformExactBlockSizes()
    {
        list($encrypted) = $this->transform->transform('foobarbazquxdoom', $context);
        list($output) = $this->transform->transform('foobarbazquxdoom', $context, true);
        $encrypted .= $output;

        $this->assertSameCiphertext($this->encrypter->encrypt('foobarbazquxdoomfoobarbazquxdoom'), $encrypted);
        $this->assertNull($context);
    }

    protected function assertSameCiphertext($expected, $actual)
    {
        $expectedVersion = bin2hex(substr($expected, 0, 2));
        $expectedIv = bin2hex(substr($expected, 2, 16));
        $expectedData = bin2hex(substr($expected, 18, -28));
        $expectedMac = bin2hex(substr($expected, -28));

        $actualVersion = bin2hex(substr($actual, 0, 2));
        $actualIv = bin2hex(substr($actual, 2, 16));
        $actualData = bin2hex(substr($actual, 18, -28));
        $actualMac = bin2hex(substr($actual, -28));

        $this->assertSame($expectedVersion, $actualVersion, 'Version mismatch');
        $this->assertSame($expectedIv, $actualIv, 'IV mismatch');
        $this->assertSame($expectedData, $actualData, 'Data mismatch');
        $this->assertSame($expectedMac, $actualMac, 'MAC mismatch');
        $this->assertSame(bin2hex($expected), bin2hex($actual), 'Ciphertext mismatch');
    }
}
