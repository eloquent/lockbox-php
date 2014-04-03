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
use Eloquent\Lockbox\Padding\PkcsPadding;
use Eloquent\Lockbox\Random\DevUrandom;
use Exception;
use PHPUnit_Framework_TestCase;
use Phake;

class PasswordEncryptTransformTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->password = 'password';
        $this->iterations = 10;
        $this->randomSource = Phake::mock('Eloquent\Lockbox\Random\RandomSourceInterface');
        $this->keyDeriver = new KeyDeriver(null, $this->randomSource);
        $this->padder = new PkcsPadding;
        $this->transform = new PasswordEncryptTransform(
            $this->password,
            $this->iterations,
            $this->keyDeriver,
            $this->randomSource,
            $this->padder
        );

        $this->base64Url = Base64Url::instance();

        Phake::when($this->randomSource)->generate(16)->thenReturn('1234567890123456');
        Phake::when($this->randomSource)->generate(64)->thenReturn('1234567890123456789012345678901234567890123456789012345678901234');

    }

    public function testConstructor()
    {
        $this->assertSame($this->password, $this->transform->password());
        $this->assertSame($this->iterations, $this->transform->iterations());
        $this->assertSame($this->keyDeriver, $this->transform->keyDeriver());
        $this->assertSame($this->randomSource, $this->transform->randomSource());
        $this->assertSame($this->padder, $this->transform->padder());
    }

    public function testConstructorDefaults()
    {
        $this->transform = new PasswordEncryptTransform($this->password, $this->iterations);

        $this->assertSame(KeyDeriver::instance(), $this->transform->keyDeriver());
        $this->assertSame(DevUrandom::instance(), $this->transform->randomSource());
        $this->assertSame(PkcsPadding::instance(), $this->transform->padder());
    }

    public function testTransform()
    {
        list($output, $buffer, $context, $error) = $this->feedTransform('foo', 'bar', 'baz', 'qux', 'dooms', 'plat');
        $expected = $this->base64Url->decode(
            'AQIAAAAKMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEy' .
            'MzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDEyMzQ1Njc4OTAxMjM0NTZplb_74ZXs48BZ' .
            '6QgffQ8xEkiQRBzIKi8Ko4tnVoT_T6Gp5NzsM5rAWms3TtutWnxbwTwuHKzlVjWo' .
            '89HxKMZu'
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
            'AQIAAAAKMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEy' .
            'MzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDEyMzQ1Njc4OTAxMjM0NTZplb_74ZXs48BZ' .
            '6QgffQ8xLtn32Sqez5sdiOXL-UkepclGdzDvz0Nd3BUA44CHw4jaMtOz4vKJAcX6' .
            'tX5AQx7EjgnCyLfLpbLURpxf1q3ueA'
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
