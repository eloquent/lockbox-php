<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Cipher;

use Eloquent\Endec\Base64\Base64Url;
use Eloquent\Lockbox\Cipher\Parameters\EncryptParameters;
use Eloquent\Lockbox\Cipher\Result\Factory\CipherResultFactory;
use Eloquent\Lockbox\Key\Key;
use Eloquent\Lockbox\Padding\PkcsPadding;
use Eloquent\Lockbox\Password\Password;
use Eloquent\Lockbox\Random\DevUrandom;
use Exception;
use PHPUnit_Framework_TestCase;
use Phake;

/**
 * @covers \Eloquent\Lockbox\Cipher\EncryptCipher
 * @covers \Eloquent\Lockbox\Cipher\AbstractEncryptCipher
 */
class EncryptCipherTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->randomSource = Phake::mock('Eloquent\Lockbox\Random\RandomSourceInterface');
        $this->padder = new PkcsPadding;
        $this->resultFactory = new CipherResultFactory;
        $this->cipher = new EncryptCipher($this->randomSource, $this->padder, $this->resultFactory);

        $this->key = new Key('1234567890123456', '1234567890123456789012345678');
        $this->iv = '1234567890123456';
        $this->parameters = new EncryptParameters($this->key, $this->iv);
        $this->parametersDefaults = new EncryptParameters($this->key);
        $this->base64Url = Base64Url::instance();

        Phake::when($this->randomSource)->generate(16)->thenReturn($this->iv);
    }

    public function testConstructor()
    {
        $this->assertSame($this->randomSource, $this->cipher->randomSource());
        $this->assertSame($this->padder, $this->cipher->padder());
        $this->assertSame($this->resultFactory, $this->cipher->resultFactory());
    }

    public function testConstructorDefaults()
    {
        $this->cipher = new EncryptCipher;

        $this->assertSame(DevUrandom::instance(), $this->cipher->randomSource());
        $this->assertSame(PkcsPadding::instance(), $this->cipher->padder());
        $this->assertSame(CipherResultFactory::instance(), $this->cipher->resultFactory());
    }

    public function testIsInitialized()
    {
        $this->assertFalse($this->cipher->isInitialized());

        $this->cipher->initialize($this->parameters);

        $this->assertTrue($this->cipher->isInitialized());
    }

    public function testInitializeFailureUnsupported()
    {
        $this->setExpectedException('Eloquent\Lockbox\Cipher\Exception\UnsupportedCipherParametersException');
        $this->cipher->initialize(new Password('password'));
    }

    public function testCipherWithKeyAndIvParameters()
    {
        $this->cipher->initialize($this->parameters);
        $output = $this->cipher->finalize('foobarbazquxdoomsplat');
        $result = $this->cipher->result();
        $expected = $this->base64Url->decode(
            'AQExMjM0NTY3ODkwMTIzNDU2T5xLPdYzBeLJW8xyiDdJlARuJu2o4QnrWgwEVekzq_uQOat_qDHhGSRzIGUQo-U-BdePDs_-jLRS8U4RCmUjyg'
        );

        $this->assertSameCiphertext($expected, $output);
        $this->assertTrue($this->cipher->isFinalized());
        $this->assertTrue($this->cipher->hasResult());
        $this->assertSame('SUCCESS', $result->type()->key());
    }

    public function testCipherWithKeyOnlyParameters()
    {
        $this->cipher->initialize($this->parametersDefaults);
        $output = $this->cipher->finalize('foobarbazquxdoomsplat');
        $result = $this->cipher->result();
        $expected = $this->base64Url->decode(
            'AQExMjM0NTY3ODkwMTIzNDU2T5xLPdYzBeLJW8xyiDdJlARuJu2o4QnrWgwEVekzq_uQOat_qDHhGSRzIGUQo-U-BdePDs_-jLRS8U4RCmUjyg'
        );

        $this->assertSameCiphertext($expected, $output);
        $this->assertTrue($this->cipher->isFinalized());
        $this->assertTrue($this->cipher->hasResult());
        $this->assertSame('SUCCESS', $result->type()->key());
    }

    public function testCipherWithKeyOnly()
    {
        $this->cipher->initialize($this->key);
        $output = $this->cipher->finalize('foobarbazquxdoomsplat');
        $result = $this->cipher->result();
        $expected = $this->base64Url->decode(
            'AQExMjM0NTY3ODkwMTIzNDU2T5xLPdYzBeLJW8xyiDdJlARuJu2o4QnrWgwEVekzq_uQOat_qDHhGSRzIGUQo-U-BdePDs_-jLRS8U4RCmUjyg'
        );

        $this->assertSameCiphertext($expected, $output);
        $this->assertTrue($this->cipher->isFinalized());
        $this->assertTrue($this->cipher->hasResult());
        $this->assertSame('SUCCESS', $result->type()->key());
    }

    public function testCipherEmpty()
    {
        $this->cipher->initialize($this->parameters);
        $output = $this->cipher->finalize();
        $result = $this->cipher->result();
        $expected = $this->base64Url->decode(
            'AQExMjM0NTY3ODkwMTIzNDU2BsV8no6a9yLYUT6rbu2PdNC4LItQ9m-F9dQ65M-pun4OnZkLrHT8zDDw0sE4Dg'
        );

        $this->assertSameCiphertext($expected, $output);
        $this->assertTrue($this->cipher->isFinalized());
        $this->assertTrue($this->cipher->hasResult());
        $this->assertSame('SUCCESS', $result->type()->key());
    }

    public function testCipherByteByByte()
    {
        $this->cipher->initialize($this->parameters);
        $input = 'foobarbazquxdoomsplat';
        $output = '';
        for ($i = 0; $i < 21; $i ++) {
            $output .= $this->cipher->process($input[$i]);
        }
        $output .= $this->cipher->finalize();
        $result = $this->cipher->result();
        $expected = $this->base64Url->decode(
            'AQExMjM0NTY3ODkwMTIzNDU2T5xLPdYzBeLJW8xyiDdJlARuJu2o4QnrWgwEVekzq_uQOat_qDHhGSRzIGUQo-U-BdePDs_-jLRS8U4RCmUjyg'
        );

        $this->assertSameCiphertext($expected, $output);
        $this->assertTrue($this->cipher->isFinalized());
        $this->assertTrue($this->cipher->hasResult());
        $this->assertSame('SUCCESS', $result->type()->key());
    }

    public function testCipherWithSmallPackets()
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
        $result = $this->cipher->result();
        $expected = $this->base64Url->decode(
            'AQExMjM0NTY3ODkwMTIzNDU2T5xLPdYzBeLJW8xyiDdJlARuJu2o4QnrWgwEVekzq_uQOat_qDHhGSRzIGUQo-U-BdePDs_-jLRS8U4RCmUjyg'
        );

        $this->assertSameCiphertext($expected, $output);
        $this->assertTrue($this->cipher->isFinalized());
        $this->assertTrue($this->cipher->hasResult());
        $this->assertSame('SUCCESS', $result->type()->key());
    }

    public function testCipherBlockByBlock()
    {
        $this->cipher->initialize($this->parameters);
        $output = '';
        $output .= $this->cipher->process('foobarbazquxdoom');
        $output .= $this->cipher->process('foobarbazquxdoom');
        $output .= $this->cipher->finalize();
        $result = $this->cipher->result();
        $expected = $this->base64Url->decode(
            'AQExMjM0NTY3ODkwMTIzNDU2T5xLPdYzBeLJW8xyiDdJlARu0_Bk3cPXHsLggdoFLPnlwR29pd_lX36Diz3sv2v6sIsAmdbSuDnDnVctQhnxXOgECTCSb8G-xnE_kmnhWk432g'
        );

        $this->assertSameCiphertext($expected, $output);
        $this->assertTrue($this->cipher->isFinalized());
        $this->assertTrue($this->cipher->hasResult());
        $this->assertSame('SUCCESS', $result->type()->key());
    }

    public function testCipherBlockByBlockProcessThenFinalize()
    {
        $this->cipher->initialize($this->parameters);
        $output = '';
        $output .= $this->cipher->process('foobarbazquxdoom');
        $output .= $this->cipher->finalize('foobarbazquxdoom');
        $result = $this->cipher->result();
        $expected = $this->base64Url->decode(
            'AQExMjM0NTY3ODkwMTIzNDU2T5xLPdYzBeLJW8xyiDdJlARu0_Bk3cPXHsLggdoFLPnlwR29pd_lX36Diz3sv2v6sIsAmdbSuDnDnVctQhnxXOgECTCSb8G-xnE_kmnhWk432g'
        );

        $this->assertSameCiphertext($expected, $output);
        $this->assertTrue($this->cipher->isFinalized());
        $this->assertTrue($this->cipher->hasResult());
        $this->assertSame('SUCCESS', $result->type()->key());
    }

    public function testInitializeAfterUse()
    {
        $this->cipher->initialize(new Key('12345678901234567890123456789012', '12345678901234567890123456789012'));
        $this->cipher->process('foobarbazquxdoomsplat');
        $this->cipher->initialize($this->parameters);
        $output = $this->cipher->finalize('foobarbazquxdoomsplat');
        $result = $this->cipher->result();
        $expected = $this->base64Url->decode(
            'AQExMjM0NTY3ODkwMTIzNDU2T5xLPdYzBeLJW8xyiDdJlARuJu2o4QnrWgwEVekzq_uQOat_qDHhGSRzIGUQo-U-BdePDs_-jLRS8U4RCmUjyg'
        );

        $this->assertSameCiphertext($expected, $output);
        $this->assertTrue($this->cipher->isFinalized());
        $this->assertTrue($this->cipher->hasResult());
        $this->assertSame('SUCCESS', $result->type()->key());
    }

    public function testResetAfterUse()
    {
        $this->cipher->reset();
        $this->cipher->initialize($this->parameters);
        $this->cipher->process('foobarbazquxdoomsplat');
        $this->cipher->reset();
        $output = $this->cipher->finalize('foobarbazquxdoomsplat');
        $result = $this->cipher->result();
        $expected = $this->base64Url->decode(
            'AQExMjM0NTY3ODkwMTIzNDU2T5xLPdYzBeLJW8xyiDdJlARuJu2o4QnrWgwEVekzq_uQOat_qDHhGSRzIGUQo-U-BdePDs_-jLRS8U4RCmUjyg'
        );

        $this->assertSameCiphertext($expected, $output);
        $this->assertTrue($this->cipher->isFinalized());
        $this->assertTrue($this->cipher->hasResult());
        $this->assertSame('SUCCESS', $result->type()->key());
    }

    public function testProcessFailureNotInitialized()
    {
        $this->setExpectedException('Eloquent\Lockbox\Cipher\Exception\CipherNotInitializedException');

        $this->cipher->process('');
    }

    public function testFinalizeFailureNotInitialized()
    {
        $this->setExpectedException('Eloquent\Lockbox\Cipher\Exception\CipherNotInitializedException');

        $this->cipher->finalize();
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
