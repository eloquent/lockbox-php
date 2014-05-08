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
use Eloquent\Lockbox\Key\KeyDeriver;
use Eloquent\Lockbox\Password\Cipher\PasswordEncryptCipher;
use Exception;
use PHPUnit_Framework_TestCase;

class PasswordEncryptTransformTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->password = 'password';
        $this->iterations = 10;
        $this->salt = '1234567890123456789012345678901234567890123456789012345678901234';
        $this->iv = '1234567890123456';
        $this->keyDeriver = new KeyDeriver;
        $this->cipher = new PasswordEncryptCipher($this->keyDeriver);
        $this->cipher->initialize($this->password, $this->iterations, $this->salt, $this->iv);
        $this->transform = new PasswordEncryptTransform($this->cipher);

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
            'AQIAAAAKMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDEyMzQ1Njc4OTAxMjM0NTZplb_74ZXs48BZ6QgffQ8xhtsSSJBEHMgqLwqji2dWhP9P8gChqeTc7DOawFprN07brVp8W8E8Lhys5VY1qPPR8SjGbg'
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
            'AQIAAAAKMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDEyMzQ1Njc4OTAxMjM0NTZplb_74ZXs48BZ6QgffQ8xhtsu2ffZKp7Pmx2I5cv5SR6lGDvJRncw789DXdwVAOOAh8OIzaHaMtOz4vKJAcX6tX5AQx7EjgnCyLfLpbLURpxf1q3ueA'
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
                $thisOutput = '';
                $consumed = 0;
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
        $expectedIterations = bin2hex(substr($expected, 2, 4));
        $expectedSalt = bin2hex(substr($expected, 6, 64));
        $expectedIv = bin2hex(substr($expected, 70, 16));
        $expectedData = bin2hex(substr($expected, 86, -32));
        $expectedMac = bin2hex(substr($expected, -32));

        $actualVersion = bin2hex(substr($actual, 0, 1));
        $actualType = bin2hex(substr($actual, 1, 1));
        $actualIterations = bin2hex(substr($actual, 2, 4));
        $actualSalt = bin2hex(substr($actual, 6, 64));
        $actualIv = bin2hex(substr($actual, 70, 16));
        $actualData = bin2hex(substr($actual, 86, -32));
        $actualMac = bin2hex(substr($actual, -32));

        $this->assertSame($expectedVersion, $actualVersion, 'Version mismatch');
        $this->assertSame($expectedType, $actualType, 'Type mismatch');
        $this->assertSame($expectedIterations, $actualIterations, 'Iterations mismatch');
        $this->assertSame($expectedSalt, $actualSalt, 'Salt mismatch');
        $this->assertSame($expectedIv, $actualIv, 'IV mismatch');
        $this->assertSame($expectedData, $actualData, 'Data mismatch');
        $this->assertSame($expectedMac, $actualMac, 'MAC mismatch');
        $this->assertSame(bin2hex($expected), bin2hex($actual), 'Ciphertext mismatch');
    }
}
