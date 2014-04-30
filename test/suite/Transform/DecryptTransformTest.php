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
use Eloquent\Lockbox\Cipher\Factory\EncryptCipherFactory;
use Eloquent\Lockbox\Key\Key;
use Eloquent\Lockbox\Padding\PkcsPadding;
use Eloquent\Lockbox\RawEncrypter;
use Eloquent\Lockbox\Transform\Factory\EncryptTransformFactory;
use PHPUnit_Framework_TestCase;
use Phake;

class DecryptTransformTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->key = new Key('1234567890123456', '1234567890123456789012345678');
        $this->unpadder = new PkcsPadding;
        $this->transform = new DecryptTransform($this->key, $this->unpadder);

        $this->version = $this->type = chr(1);
        $this->iv = '1234567890123456';
        $this->randomSource = Phake::mock('Eloquent\Lockbox\Random\RandomSourceInterface');
        $this->encrypter = new BoundEncrypter(
            $this->key,
            new RawEncrypter(new EncryptTransformFactory(new EncryptCipherFactory($this->randomSource)))
        );

        Phake::when($this->randomSource)->generate(16)->thenReturn($this->iv);
    }

    public function testConstructor()
    {
        $this->assertSame($this->key, $this->transform->key());
        $this->assertSame($this->unpadder, $this->transform->unpadder());
    }

    public function testConstructorDefaults()
    {
        $this->transform = new DecryptTransform($this->key);

        $this->assertSame(PkcsPadding::instance(), $this->transform->unpadder());
    }

    public function transformData()
    {
        return array(
            'Partial block'             => array('foobar'),
            'One block'                 => array('foobarbazquxdoom'),
            'One block plus partial'    => array('foobarbazquxdoomfoobar'),
            'Two blocks'                => array('foobarbazquxdoomfoobarbazquxdoom'),
            'Two blocks plus partial'   => array('foobarbazquxdoomfoobarbazquxdoomfoobar'),
            'Three blocks'              => array('foobarbazquxdoomfoobarbazquxdoomfoobarbazquxdoom'),
            'Three blocks plus partial' => array('foobarbazquxdoomfoobarbazquxdoomfoobarbazquxdoomfoobar'),
        );
    }

    /**
     * @dataProvider transformData
     */
    public function testTransform($input)
    {
        $encrypted = $this->encrypter->encrypt($input);
        list($output, $buffer, $context, $error) = $this->feedTransform($encrypted);
        $result = $this->transform->result();

        $this->assertNotNull($result);
        $this->assertTrue($result->isSuccessful());
        $this->assertNull($result->data());
        $this->assertSame(array($input, '', null), array($output, $buffer, $error));
        $this->assertNull($context);
    }

    /**
     * @dataProvider transformData
     */
    public function testTransformByteByByte($input)
    {
        $encrypted = $this->encrypter->encrypt($input);
        $chunks = str_split($encrypted);
        array_unshift($chunks, '');
        list($output, $buffer, $context, $error) = $this->feedTransform($chunks);
        $result = $this->transform->result();

        $this->assertNotNull($result);
        $this->assertTrue($result->isSuccessful());
        $this->assertNull($result->data());
        $this->assertSame(array($input, '', null), array($output, $buffer, $error));
        $this->assertNull($context);
    }

    public function testTransformWithExactSectionSizes()
    {
        $input = 'foobarbazquxdoomfoobarbazquxdoomfoobarbazquxdoom';
        $encrypted = $this->encrypter->encrypt($input);

        $this->assertSame(118, strlen($encrypted));

        list($output, $buffer, $context, $error) = $this->feedTransform(
            substr($encrypted, 0, 1),   // version
            substr($encrypted, 1, 1),   // type
            substr($encrypted, 2, 16),  // IV
            substr($encrypted, 18, 18), // block 0
            substr($encrypted, 36, 18), // block 1
            substr($encrypted, 54, 18), // block 2
            substr($encrypted, 72, 18), // padding block
            substr($encrypted, 90)      // MAC
        );
        $result = $this->transform->result();

        $this->assertNotNull($result);
        $this->assertTrue($result->isSuccessful());
        $this->assertNull($result->data());
        $this->assertSame(array($input, '', null), array($output, $buffer, $error));
        $this->assertNull($context);
    }

    public function transformFailureData()
    {
        $this->version = $this->type = chr(1);
        $this->iv = '1234567890123456';
        $this->key = new Key('1234567890123456', '1234567890123456789012345678');

        return array(
            'Empty' => array(
                '',
                'INVALID_SIZE',
            ),
            'Unsupported version' => array(
                chr(111) . $this->type . $this->iv . '123456789012345678' .
                $this->authenticate(chr(111) . '12345678901234567' . '1234567890123456'),
                'UNSUPPORTED_VERSION',
            ),
            'Empty type' => array(
                $this->version,
                'INVALID_SIZE',
            ),
            'Unsupported type' => array(
                $this->version . chr(111) . $this->iv . '123456789012345678' .
                $this->authenticate($this->version . chr(111) . '1234567890123456' . '1234567890123456'),
                'UNSUPPORTED_TYPE',
            ),
            'Empty IV' => array(
                $this->version . $this->type,
                'INVALID_SIZE',
            ),
            'Partial IV' => array(
                $this->version . $this->type . '123456789012345',
                'INVALID_SIZE',
            ),
            'Empty data and MAC' => array(
                $this->version . $this->type . $this->iv,
                'INVALID_SIZE',
            ),
            'Empty data' => array(
                $this->version . $this->type . $this->iv . '123456789012345678901234567',
                'INVALID_SIZE',
            ),
            'Not enough data for MAC' => array(
                $this->version . $this->type . $this->iv .
                $this->encryptAndPadAes('1234567890123456') . '123456789012345678901234567',
                'INVALID_SIZE',
            ),
            'Invalid data length' => array(
                $this->version . $this->type . $this->iv .
                $this->encryptAes('1234567890123456') . '12' .
                substr($this->encryptAndPadAes('1234567890123456'), 0, 15) . '12' .
                '1234567890123456789012345678',
                'INVALID_SIZE',
            ),
            'Bad block MAC' => array(
                $this->version . $this->type . $this->iv .
                substr($this->encryptAndPadAes('1234567890123456'), 0, 16) .
                $this->authenticate(substr($this->encryptAndPadAes('1234567890123456'), 0, 16), 2) .
                substr($this->encryptAndPadAes('1234567890123456'), 16) .
                '12' .
                '1234567890123456789012345678',
                'INVALID_MAC',
            ),
            'Bad MAC' => array(
                $this->version . $this->type . $this->iv .
                substr($this->encryptAndPadAes('1234567890123456'), 0, 16) .
                $this->authenticate(substr($this->encryptAndPadAes('1234567890123456'), 0, 16), 2) .
                substr($this->encryptAndPadAes('1234567890123456'), 16) .
                $this->authenticate(substr($this->encryptAndPadAes('1234567890123456'), 16), 2) .
                '1234567890123456789012345678',
                'INVALID_MAC',
            ),
            'Bad AES data' => array(
                $this->version . $this->type . $this->iv .
                'foobarbazquxdoom' . $this->authenticate('foobarbazquxdoom', 2) .
                $this->authenticate($this->version . $this->type . $this->iv .'foobarbazquxdoom'),
                'INVALID_PADDING',
            ),
            'Bad padding' => array(
                $this->version . $this->type . $this->iv .
                $this->encryptAes('1234567890123456') .
                $this->authenticate($this->encryptAes('1234567890123456'), 2) .
                $this->authenticate(
                    $this->version . $this->type . $this->iv . $this->encryptAes('1234567890123456')
                ),
                'INVALID_PADDING',
            ),
        );
    }

    /**
     * @dataProvider transformFailureData
     */
    public function testTransformFailure($input, $expected)
    {
        list($output, $buffer, $context, $error) = $this->feedTransform($input);
        $result = $this->transform->result();

        $this->assertNotNull($result);
        $this->assertFalse($result->isSuccessful());
        $this->assertSame($expected, $result->type()->key());
        $this->assertNotNull($error);
        $this->assertSame($expected, $error);
        $this->assertSame('', $output);
        $this->assertNull($context);
    }

    public function testTransformFailureAfterSuccessfulBlocks()
    {
        $block = $this->encryptAes('1234567890123456');
        list($output, $buffer, $context, $error) = $this->feedTransform(
            $this->version . $this->type . $this->iv .
            $block . $this->authenticate($block, 2) .
            $block . $this->authenticate($block, 2) .
            $block . $this->authenticate($block, 2) .
            $block . $this->authenticate($block, 2),
            $this->authenticate($this->version . $this->type . $this->iv . $block . $block . $block . $block)
        );
        $result = $this->transform->result();

        $this->assertNotNull($result);
        $this->assertFalse($result->isSuccessful());
        $this->assertSame('INVALID_PADDING', $result->type()->key());
        $this->assertNotNull($error);
        $this->assertSame('INVALID_PADDING', $error);
        $this->assertSame('1234567890123456', $output);
        $this->assertNull($context);
    }

    public function testTransformAfterFailure()
    {
        $this->transform->transform(str_repeat(' ', 200), $context);
        list($data, $consumed, $error) = $this->transform->transform('', $context, true);

        $this->assertSame('', $data);
        $this->assertSame(0, $consumed);
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

            $thisOutput = '';
            $consumed = 0;
            list($thisOutput, $consumed, $error) = $this->transform->transform($buffer, $context, $index === $lastIndex);
            if (null !== $error) {
                $error = $error->type()->key();

                break;
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

    protected function encryptAes($data)
    {
        return mcrypt_encrypt(
            MCRYPT_RIJNDAEL_128,
            $this->key->encryptionSecret(),
            $data,
            MCRYPT_MODE_CBC,
            '1234567890123456'
        );
    }

    protected function encryptAndPadAes($data)
    {
        return $this->encryptAes($this->pad($data));
    }

    protected function pad($data)
    {
        $padSize = intval(16 - (strlen($data) % 16));

        return $data . str_repeat(chr($padSize), $padSize);
    }

    protected function authenticate($data, $size = null)
    {
        $mac = hash_hmac(
            'sha' . $this->key->authenticationSecretBits(),
            $data,
            $this->key->authenticationSecret(),
            true
        );

        if (null !== $size) {
            $mac = substr($mac, 0, $size);
        }

        return $mac;
    }
}
