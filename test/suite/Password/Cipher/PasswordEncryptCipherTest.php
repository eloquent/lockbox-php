<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Password\Cipher;

use Eloquent\Endec\Base64\Base64Url;
use Eloquent\Lockbox\Key\KeyDeriver;
use Eloquent\Lockbox\Padding\PkcsPadding;
use Eloquent\Lockbox\Password\Cipher\Parameters\PasswordEncryptCipherParameters;
use Eloquent\Lockbox\Random\DevUrandom;
use Exception;
use PHPUnit_Framework_TestCase;
use Phake;

class PasswordEncryptCipherTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->randomSource = Phake::mock('Eloquent\Lockbox\Random\RandomSourceInterface');
        $this->keyDeriver = new KeyDeriver(null, $this->randomSource);
        $this->padder = new PkcsPadding;
        $this->cipher = new PasswordEncryptCipher($this->keyDeriver, $this->randomSource, $this->padder);

        $this->password = 'password';
        $this->iterations = 10;
        $this->salt = '1234567890123456789012345678901234567890123456789012345678901234';
        $this->iv = '1234567890123456';
        $this->parameters = new PasswordEncryptCipherParameters(
            $this->password,
            $this->iterations,
            $this->salt,
            $this->iv
        );
        $this->base64Url = Base64Url::instance();

        Phake::when($this->randomSource)->generate(64)->thenReturn($this->salt);
        Phake::when($this->randomSource)->generate(16)->thenReturn($this->iv);
    }

    public function testConstructor()
    {
        $this->assertSame($this->keyDeriver, $this->cipher->keyDeriver());
        $this->assertSame($this->randomSource, $this->cipher->randomSource());
        $this->assertSame($this->padder, $this->cipher->padder());
    }

    public function testConstructorDefaults()
    {
        $this->cipher = new PasswordEncryptCipher;

        $this->assertSame(KeyDeriver::instance(), $this->cipher->keyDeriver());
        $this->assertSame(DevUrandom::instance(), $this->cipher->randomSource());
        $this->assertSame(PkcsPadding::instance(), $this->cipher->padder());
    }

    public function testCipher()
    {
        $this->cipher->initialize($this->parameters);
        $output = '';
        $output .= $this->cipher->process('foo');
        $output .= $this->cipher->process('bar');
        $output .= $this->cipher->process('baz');
        $output .= $this->cipher->process('qux');
        $output .= $this->cipher->process('dooms');
        $output .= $this->cipher->process('plat');
        $output .= $this->cipher->finalize();
        $expected = $this->base64Url->decode(
            'AQIAAAAKMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDEyMzQ1Njc4OTAxMjM0NTZplb_74ZXs48BZ6QgffQ8xhtsSSJBEHMgqLwqji2dWhP9P8gChqeTc7DOawFprN07brVp8W8E8Lhys5VY1qPPR8SjGbg'
        );

        $this->assertSameCiphertext($expected, $output);
        $this->assertTrue($this->cipher->isFinalized());
        $this->assertTrue($this->cipher->hasResult());
        $this->assertTrue($this->cipher->result()->isSuccessful());
    }

    public function testCipherExactBlockSizes()
    {
        $this->cipher->initialize($this->parameters);
        $output = '';
        $output .= $this->cipher->process('foobarbazquxdoom');
        $output .= $this->cipher->process('foobarbazquxdoom');
        $output .= $this->cipher->finalize();
        $expected = $this->base64Url->decode(
            'AQIAAAAKMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDEyMzQ1Njc4OTAxMjM0NTZplb_74ZXs48BZ6QgffQ8xhtsu2ffZKp7Pmx2I5cv5SR6lGDvJRncw789DXdwVAOOAh8OIzaHaMtOz4vKJAcX6tX5AQx7EjgnCyLfLpbLURpxf1q3ueA'
        );

        $this->assertSameCiphertext($expected, $output);
        $this->assertTrue($this->cipher->isFinalized());
        $this->assertTrue($this->cipher->hasResult());
        $this->assertTrue($this->cipher->result()->isSuccessful());
    }

    public function testCipherEmpty()
    {
        $this->cipher->initialize($this->parameters);
        $output = $this->cipher->finalize('');
        $expected = $this->base64Url->decode(
            'AQIAAAAKMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDEyMzQ1Njc4OTAxMjM0NTZRaA7HLiTfD-B0SQrtg_ea5B86TwcwY62uLJdEPHsiX10LKQ1P55HLko_TAiPDIGcDmg'
        );

        $this->assertSameCiphertext($expected, $output);
        $this->assertTrue($this->cipher->isFinalized());
        $this->assertTrue($this->cipher->hasResult());
        $this->assertTrue($this->cipher->result()->isSuccessful());
    }

    public function testCipherFinalizeOnly()
    {
        $this->cipher->initialize($this->parameters);
        $output = $this->cipher->finalize();
        $expected = $this->base64Url->decode(
            'AQIAAAAKMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDEyMzQ1Njc4OTAxMjM0NTZRaA7HLiTfD-B0SQrtg_ea5B86TwcwY62uLJdEPHsiX10LKQ1P55HLko_TAiPDIGcDmg'
        );

        $this->assertSameCiphertext($expected, $output);
        $this->assertTrue($this->cipher->isFinalized());
        $this->assertTrue($this->cipher->hasResult());
        $this->assertTrue($this->cipher->result()->isSuccessful());
    }

    public function testProcessFailureFinalized()
    {
        $this->cipher->initialize($this->parameters);
        $this->cipher->finalize();
        $this->setExpectedException('Eloquent\Lockbox\Cipher\Exception\CipherFinalizedException');

        $this->cipher->process('');
    }

    public function testFinalizeFailureFinalized()
    {
        $this->cipher->initialize($this->parameters);
        $this->cipher->finalize();
        $this->setExpectedException('Eloquent\Lockbox\Cipher\Exception\CipherFinalizedException');

        $this->cipher->finalize();
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
