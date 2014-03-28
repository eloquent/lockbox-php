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
use Eloquent\Lockbox\BoundEncrypter;
use Eloquent\Lockbox\Encrypter;
use Eloquent\Lockbox\Key\Key;
use Eloquent\Lockbox\Random\DevUrandom;
use Eloquent\Lockbox\RawEncrypter;
use Eloquent\Lockbox\Transform\Factory\EncryptTransformFactory;
use Exception;
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

        $this->base64Url = Base64Url::instance();
        $this->encrypter = new BoundEncrypter($this->key, new RawEncrypter(new EncryptTransformFactory($this->randomSource)));

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
        list($output, $buffer, $context, $error) = $this->feedTransform('foo', 'bar', 'baz', 'qux', 'dooms', 'plat');
        $expected = $this->base64Url->decode(
            'AQExMjM0NTY3ODkwMTIzNDU2T5xLPdYzBeLJW8xyiDdJlCbtqOEJ61oMBFXpM6v7kDmoMeEZJHMgZRCj5T4F148Oz_6MtFLxThEKZSPK'
        );

        $this->assertSameCiphertext($expected, $output);
        $this->assertSame('', $buffer);
        $this->assertNull($context);
        $this->assertNull($error);
    }

    public function testTransformExactBlockSizes()
    {
        list($output, $buffer, $context, $error) = $this->feedTransform('foobarbazquxdoom', 'foobarbazquxdoom');
        $expected = $this->base64Url->decode(
            'AQExMjM0NTY3ODkwMTIzNDU2T5xLPdYzBeLJW8xyiDdJlNPwZN3D1x7C4IHaBSz5' .
            '5cGl3-VffoOLPey_a_qwiwCZuDnDnVctQhnxXOgECTCSb8G-xnE_kmnhWk432g'
        );

        $this->assertSameCiphertext($expected, $output);
        $this->assertSame('', $buffer);
        $this->assertNull($context);
        $this->assertNull($error);
    }

    protected function feedTransform($packets)
    {
        if (!is_array($packets)) {
            $packets = func_get_args();
        }

        $output = '';
        $buffer = '';
        $lastIndex = count($packets) - 1;
        $error = null;
        foreach ($packets as $index => $data) {
            $buffer .= $data;

            try {
                list($thisOutput, $consumed) = $this->transform->transform($buffer, $context, $index === $lastIndex);
            } catch (Exception $error) {
                $error = strval($error);
            }

            $output .= $thisOutput;
            if (strlen($buffer) === $consumed) {
                $buffer = '';
            } else {
                $buffer = substr($buffer, $consumed);
            }
        }

        return array($output, $buffer, $context, $error);
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
