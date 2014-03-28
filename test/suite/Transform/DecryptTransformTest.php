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
use Eloquent\Lockbox\RawEncrypter;
use Exception;
use PHPUnit_Framework_TestCase;
use Phake;

class DecryptTransformTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->key = new Key('1234567890123456', '1234567890123456789012345678');
        $this->transform = new DecryptTransform($this->key);

        $this->iv = '1234567890123456';
        $this->randomSource = Phake::mock('Eloquent\Lockbox\Random\RandomSourceInterface');
        $this->encrypter = new BoundEncrypter($this->key, new RawEncrypter($this->randomSource));

        Phake::when($this->randomSource)->generate(16)->thenReturn($this->iv);
    }

    public function testConstructor()
    {
        $this->assertSame($this->key, $this->transform->key());
    }

    public function transformData()
    {
        return array(
            'Partial block'              => array('foobar'),
            'One block'                  => array('foobarbazquxdoom'),
            'One block plus partial'     => array('foobarbazquxdoomfoobar'),
            'Two blocks'                 => array('foobarbazquxdoomfoobarbazquxdoom'),
            'Two blocks plus partial'    => array('foobarbazquxdoomfoobarbazquxdoomfoobar'),
            'Three blocks'               => array('foobarbazquxdoomfoobarbazquxdoomfoobarbazquxdoom'),
            'Three blocks plus partial'  => array('foobarbazquxdoomfoobarbazquxdoomfoobarbazquxdoomfoobar'),
        );
    }

    /**
     * @dataProvider transformData
     */
    public function testTransform($input)
    {
        $encrypted = $this->encrypter->encrypt($input);
        list($output, $buffer, $context, $error) = $this->feedTransform($encrypted);

        $this->assertSame(array($input, '', null), array($output, $buffer, $error));
        $this->assertNull($context);
    }

    /**
     * @dataProvider transformData
     */
    public function testTransformByteByByte($input)
    {
        $encrypted = $this->encrypter->encrypt($input);
        list($output, $buffer, $context, $error) = $this->feedTransform(str_split($encrypted));

        $this->assertSame(array($input, '', null), array($output, $buffer, $error));
        $this->assertNull($context);
    }

    public function testTransformWithExactSectionSizes()
    {
        $input = 'foobarbazquxdoomfoobarbazquxdoomfoobarbazquxdoom';
        $encrypted = $this->encrypter->encrypt($input);

        $this->assertSame(110, strlen($encrypted));

        list($output, $buffer, $context, $error) = $this->feedTransform(
            substr($encrypted, 0, 2),   // version
            substr($encrypted, 2, 16),  // IV
            substr($encrypted, 18, 16), // block 0
            substr($encrypted, 34, 16), // block 1
            substr($encrypted, 50, 16), // block 2
            substr($encrypted, 66, 16), // padding block
            substr($encrypted, 82)      // MAC
        );

        $this->assertSame(array($input, '', null), array($output, $buffer, $error));
        $this->assertNull($context);
    }

    public function transformFailureData()
    {
        $this->key = new Key('1234567890123456', '1234567890123456789012345678');

        return array(
            'Empty' => array(
                '',
            ),
            'Partial version'=> array(
                '1',
            ),
            'Unsupported version' => array(
                pack('n', 111),
            ),
            'Empty IV' => array(
                pack('n', 1),
            ),
            'Partial IV' => array(
                pack('n', 1) . '123456789012345',
            ),
            'Empty data and MAC' => array(
                pack('n', 1) . '1234567890123456',
            ),
            'Empty data' => array(
                pack('n', 1) . '1234567890123456' . '123456789012345678901234567',
            ),
            'Not enough data for MAC' => array(
                pack('n', 1) . '1234567890123456' .
                $this->encryptAndPadAes('1234567890123456') . '123456789012345678901234567',
            ),
            'Invalid data length' => array(
                pack('n', 1) . '1234567890123456' .
                $this->encryptAes('1234567890123456') .
                substr($this->encryptAndPadAes('1234567890123456'), 0, 15) .
                '1234567890123456789012345678',
            ),
            'Bad MAC' => array(
                pack('n', 1) . '1234567890123456' .
                $this->encryptAndPadAes('1234567890123456') .
                '1234567890123456789012345678',
            ),
            'Bad AES data' => array(
                pack('n', 1) . '1234567890123456' . '1234567890123457' .
                $this->authenticationCode(pack('n', 1) . '1234567890123456' . '1234567890123457'),
            ),
            'Bad padding' => array(
                pack('n', 1) . '1234567890123456' .
                $this->encryptAes('1234567890123456') .
                $this->authenticationCode(pack('n', 1) . '1234567890123456' . $this->encryptAes('1234567890123456')),
            ),
        );
    }

    /**
     * @dataProvider transformFailureData
     */
    public function testTransformFailure($input)
    {
        list($output, $buffer, $context, $error) = $this->feedTransform($input);

        $this->assertNotNull($error);
        $this->assertRegExp("/'Eloquent\\\\Lockbox\\\\Exception\\\\DecryptionFailedException'/", $error);
        $this->assertSame('', $output);
        $this->assertNull($context);
    }

    public function testTransformFailureAfterSuccessfulBlocks()
    {
        list($output, $buffer, $context, $error) = $this->feedTransform(
            pack('n', 1) . '1234567890123456' .
                $this->encryptAes('1234567890123456') .
                $this->encryptAes('1234567890123456') .
                $this->encryptAes('1234567890123456') .
                $this->encryptAes('1234567890123456'),
            $this->authenticationCode(
                pack('n', 1) . '1234567890123456' .
                    $this->encryptAes('1234567890123456') .
                    $this->encryptAes('1234567890123456') .
                    $this->encryptAes('1234567890123456') .
                    $this->encryptAes('1234567890123456')
            )
        );

        $this->assertNotNull($error);
        $this->assertRegExp("/'Eloquent\\\\Lockbox\\\\Exception\\\\DecryptionFailedException'/", $error);
        $this->assertSame('1234567890123456', $output);
        $this->assertNull($context);
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
