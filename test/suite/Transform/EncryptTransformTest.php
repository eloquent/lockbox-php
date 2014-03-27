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

use Eloquent\Endec\Base64\Base64Url;
use Eloquent\Endec\Base64\Base64UrlEncodeTransform;
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
        $this->encodingTransform = new Base64UrlEncodeTransform;
        $this->transform = new EncryptTransform($this->key, $this->randomSource, $this->encodingTransform);

        $this->encrypter = new BoundEncrypter($this->key, new Encrypter(new RawEncrypter($this->randomSource)));
        $this->base64Url = Base64Url::instance();

        Phake::when($this->randomSource)->generate(16)->thenReturn('1234567890123456');
    }

    public function testConstructor()
    {
        $this->assertSame($this->key, $this->transform->key());
        $this->assertSame($this->randomSource, $this->transform->randomSource());
        $this->assertSame($this->encodingTransform, $this->transform->encodingTransform());
    }

    public function testConstructorDefaults()
    {
        $this->transform = new EncryptTransform($this->key);

        $this->assertSame(DevUrandom::instance(), $this->transform->randomSource());
        $this->assertSame(Base64UrlEncodeTransform::instance(), $this->transform->encodingTransform());
    }

    public function testTransform()
    {
        $encrypted = '';
        foreach (array('foo', 'bar', 'baz', 'qux', 'dooms', 'plat') as $data) {
            list($output) = $this->transform->transform($data, $context);
            $encrypted .= $output;
        }
        list($output) = $this->transform->transform('', $context, true);
        $encrypted .= $output;

        $this->assertSameCiphertext($this->encrypter->encrypt('foobarbazquxdoomsplat'), $encrypted);
    }

    public function testTransformExactBlockSizes()
    {
        list($encrypted) = $this->transform->transform('foobarbazquxdoom', $context);
        list($output) = $this->transform->transform('foobarbazquxdoom', $context, true);
        $encrypted .= $output;

        $this->assertSameCiphertext($this->encrypter->encrypt('foobarbazquxdoomfoobarbazquxdoom'), $encrypted);
    }

    protected function assertSameCiphertext($expected, $actual)
    {
        $expectedRaw = $this->base64Url->decode($expected);
        $expectedVersion = $this->base64Url->encode(substr($expectedRaw, 0, 2));
        $expectedIv = $this->base64Url->encode(substr($expectedRaw, 2, 16));
        $expectedMac = $this->base64Url->encode(substr($expectedRaw, -28));
        $expectedData = $this->base64Url->encode(substr($expectedRaw, 18, -28));

        $actualRaw = $this->base64Url->decode($actual);
        $actualVersion = $this->base64Url->encode(substr($actualRaw, 0, 2));
        $actualIv = $this->base64Url->encode(substr($actualRaw, 2, 16));
        $actualMac = $this->base64Url->encode(substr($actualRaw, -28));
        $actualData = $this->base64Url->encode(substr($actualRaw, 18, -28));

        $this->assertSame($expectedVersion, $actualVersion, 'Version mismatch');
        $this->assertSame($expectedIv, $actualIv, 'IV mismatch');
        $this->assertSame($expectedMac, $actualMac, 'MAC mismatch');
        $this->assertSame($expectedData, $actualData, 'Data mismatch');
        $this->assertSame($expected, $actual, 'Ciphertext mismatch');
    }
}
