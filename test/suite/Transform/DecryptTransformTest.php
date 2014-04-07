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
        $this->encrypter = new BoundEncrypter($this->key, new RawEncrypter(new EncryptTransformFactory($this->randomSource)));

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

        $this->assertSame(110, strlen($encrypted));

        list($output, $buffer, $context, $error) = $this->feedTransform(
            substr($encrypted, 0, 1),   // version
            substr($encrypted, 1, 1),   // type
            substr($encrypted, 2, 16),  // IV
            substr($encrypted, 18, 16), // block 0
            substr($encrypted, 34, 16), // block 1
            substr($encrypted, 50, 16), // block 2
            substr($encrypted, 66, 16), // padding block
            substr($encrypted, 82)      // MAC
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
                'INSUFFICIENT_DATA',
            ),
            'Unsupported version' => array(
                chr(111),
                'UNSUPPORTED_VERSION',
            ),
            'Empty type' => array(
                $this->version,
                'INSUFFICIENT_DATA',
            ),
            'Unsupported type' => array(
                $this->version . chr(111),
                'UNSUPPORTED_TYPE',
            ),
            'Empty IV' => array(
                $this->version . $this->type,
                'INSUFFICIENT_DATA',
            ),
            'Partial IV' => array(
                $this->version . $this->type . '123456789012345',
                'INSUFFICIENT_DATA',
            ),
            'Empty data and MAC' => array(
                $this->version . $this->type . $this->iv,
                'INSUFFICIENT_DATA',
            ),
            'Empty data' => array(
                $this->version . $this->type . $this->iv . '123456789012345678901234567',
                'INSUFFICIENT_DATA',
            ),
            'Not enough data for MAC' => array(
                $this->version . $this->type . $this->iv .
                $this->encryptAndPadAes('1234567890123456') . '123456789012345678901234567',
                'INVALID_MAC',
            ),
            'Invalid data length' => array(
                $this->version . $this->type . $this->iv .
                $this->encryptAes('1234567890123456') .
                substr($this->encryptAndPadAes('1234567890123456'), 0, 15) .
                '1234567890123456789012345678',
                'INVALID_MAC',
            ),
            'Bad MAC' => array(
                $this->version . $this->type . $this->iv .
                $this->encryptAndPadAes('1234567890123456') .
                '1234567890123456789012345678',
                'INVALID_MAC',
            ),
            'Bad AES data' => array(
                $this->version . $this->type . $this->iv . '1234567890123457' .
                $this->authenticationCode($this->version . $this->type . $this->iv . '1234567890123457'),
                'INVALID_PADDING',
            ),
            'Bad padding' => array(
                $this->version . $this->type . $this->iv .
                $this->encryptAes('1234567890123456') .
                $this->authenticationCode($this->version . $this->type . $this->iv . $this->encryptAes('1234567890123456')),
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
        list($output, $buffer, $context, $error) = $this->feedTransform(
            $this->version . $this->type . $this->iv .
                $this->encryptAes('1234567890123456') .
                $this->encryptAes('1234567890123456') .
                $this->encryptAes('1234567890123456') .
                $this->encryptAes('1234567890123456'),
            $this->authenticationCode(
                $this->version . $this->type . $this->iv .
                    $this->encryptAes('1234567890123456') .
                    $this->encryptAes('1234567890123456') .
                    $this->encryptAes('1234567890123456') .
                    $this->encryptAes('1234567890123456')
            )
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

    protected function authenticationCode($data)
    {
        return hash_hmac(
            'sha224',
            $data,
            $this->key->authenticationSecret(),
            true
        );
    }
}
