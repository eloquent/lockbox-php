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
use Eloquent\Lockbox\Cipher\EncryptCipher;
use Eloquent\Lockbox\Key\Key;
use Eloquent\Lockbox\Padding\PkcsPadding;
use Eloquent\Lockbox\Random\DevUrandom;
use Exception;
use PHPUnit_Framework_TestCase;
use Phake;

class EncryptTransformTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->key = new Key('1234567890123456', '1234567890123456789012345678');
        $this->iv = '1234567890123456';
        $this->cipher = new EncryptCipher($this->key, $this->iv);
        $this->transform = new EncryptTransform($this->cipher);

        $this->base64Url = Base64Url::instance();
    }

    public function testConstructor()
    {
        $this->assertSame($this->cipher, $this->transform->cipher());
    }

    public function testTransform()
    {
        list($output, $buffer, $context, $error) = $this->feedTransform('foo', 'bar', 'baz', 'qux', 'dooms', 'plat');
        $expected = $this->base64Url->decode(
            'AQExMjM0NTY3ODkwMTIzNDU2T5xLPdYzBeLJW8xyiDdJlARuJu2o4QnrWgwEVekzq_uQOat_qDHhGSRzIGUQo-U-BdePDs_-jLRS8U4RCmUjyg'
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
            'AQExMjM0NTY3ODkwMTIzNDU2T5xLPdYzBeLJW8xyiDdJlARu0_Bk3cPXHsLggdoFLPnlwR29pd_lX36Diz3sv2v6sIsAmdbSuDnDnVctQhnxXOgECTCSb8G-xnE_kmnhWk432g'
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
        $expectedVersion = bin2hex(substr($expected, 0, 1));
        $expectedType = bin2hex(substr($expected, 1, 1));
        $expectedIv = bin2hex(substr($expected, 2, 16));
        $expectedData = bin2hex(substr($expected, 18, -28));
        $expectedMac = bin2hex(substr($expected, -28));

        $actualVersion = bin2hex(substr($actual, 0, 1));
        $actualType = bin2hex(substr($actual, 1, 1));
        $actualIv = bin2hex(substr($actual, 2, 16));
        $actualData = bin2hex(substr($actual, 18, -28));
        $actualMac = bin2hex(substr($actual, -28));

        $this->assertSame($expectedVersion, $actualVersion, 'Version mismatch');
        $this->assertSame($expectedType, $actualType, 'Type mismatch');
        $this->assertSame($expectedIv, $actualIv, 'IV mismatch');
        $this->assertSame($expectedData, $actualData, 'Data mismatch');
        $this->assertSame($expectedMac, $actualMac, 'MAC mismatch');
        $this->assertSame(bin2hex($expected), bin2hex($actual), 'Ciphertext mismatch');
    }
}
