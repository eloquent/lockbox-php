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

use Eloquent\Lockbox\Key\KeyDeriver;
use Eloquent\Lockbox\Padding\PkcsPadding;
use Eloquent\Lockbox\Password\BoundPasswordEncrypter;
use Eloquent\Lockbox\Password\RawPasswordEncrypter;
use Eloquent\Lockbox\Transform\Factory\PasswordEncryptTransformFactory;
use PHPUnit_Framework_TestCase;
use Phake;

class PasswordDecryptTransformTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->password = 'password';
        $this->randomSource = Phake::mock('Eloquent\Lockbox\Random\RandomSourceInterface');
        $this->keyDeriver = new KeyDeriver(null, $this->randomSource);
        $this->unpadder = new PkcsPadding;
        $this->transform = new PasswordDecryptTransform($this->password, $this->keyDeriver, $this->unpadder);

        $this->version = chr(1);
        $this->type = chr(2);
        $this->iterations = 10;
        $this->iterationsData = pack('N', $this->iterations);
        $this->salt = '1234567890123456789012345678901234567890123456789012345678901234';
        $this->iv = '1234567890123456';
        $this->encrypter = new BoundPasswordEncrypter(
            $this->password,
            $this->iterations,
            new RawPasswordEncrypter(new PasswordEncryptTransformFactory($this->keyDeriver, $this->randomSource))
        );

        Phake::when($this->randomSource)->generate(64)->thenReturn($this->salt);
        Phake::when($this->randomSource)->generate(16)->thenReturn($this->iv);

        list($this->key) = $this->keyDeriver->deriveKeyFromPassword($this->password, $this->iterations, $this->salt);
    }

    public function testConstructor()
    {
        $this->assertSame($this->password, $this->transform->password());
        $this->assertSame($this->keyDeriver, $this->transform->keyDeriver());
        $this->assertSame($this->unpadder, $this->transform->unpadder());
    }

    public function testConstructorDefaults()
    {
        $this->transform = new PasswordDecryptTransform($this->password);

        $this->assertSame(KeyDeriver::instance(), $this->transform->keyDeriver());
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
        $this->assertSame($this->iterations, $result->iterations());
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
        $this->assertSame($this->iterations, $result->iterations());
        $this->assertSame(array($input, '', null), array($output, $buffer, $error));
        $this->assertNull($context);
    }

    public function testTransformWithExactSectionSizes()
    {
        $input = 'foobarbazquxdoomfoobarbazquxdoomfoobarbazquxdoom';
        $encrypted = $this->encrypter->encrypt($input);

        $this->assertSame(190, strlen($encrypted));

        list($output, $buffer, $context, $error) = $this->feedTransform(
            substr($encrypted, 0, 1),    // version
            substr($encrypted, 1, 1),    // type
            substr($encrypted, 2, 4),    // iterations
            substr($encrypted, 6, 64),   // salt
            substr($encrypted, 70, 18),  // IV
            substr($encrypted, 88, 18),  // block 0
            substr($encrypted, 106, 18), // block 1
            substr($encrypted, 124, 18), // block 2
            substr($encrypted, 142, 18), // padding block
            substr($encrypted, 160)      // MAC
        );
        $result = $this->transform->result();

        $this->assertNotNull($result);
        $this->assertTrue($result->isSuccessful());
        $this->assertNull($result->data());
        $this->assertSame($this->iterations, $result->iterations());
        $this->assertSame(array($input, '', null), array($output, $buffer, $error));
        $this->assertNull($context);
    }

    public function transformFailureData()
    {
        $this->password = 'password';
        $this->version = chr(1);
        $this->type = chr(2);
        $this->iterations = 10;
        $this->iterationsData = pack('N', $this->iterations);
        $this->salt = '1234567890123456789012345678901234567890123456789012345678901234';
        $this->iv = '1234567890123456';
        $this->randomSource = Phake::mock('Eloquent\Lockbox\Random\RandomSourceInterface');
        $this->keyDeriver = new KeyDeriver(null, $this->randomSource);
        list($this->key) = $this->keyDeriver->deriveKeyFromPassword($this->password, $this->iterations, $this->salt);
        Phake::when($this->randomSource)->generate(64)->thenReturn($this->salt);
        Phake::when($this->randomSource)->generate(16)->thenReturn($this->iv);

        return array(
            'Empty' => array(
                '',
                'INVALID_SIZE',
            ),
            'Unsupported version' => array(
                chr(111) . $this->type . $this->iterationsData . $this->salt . $this->iv .
                $this->encryptAndPadAes('1234567890123456') .
                '12345678901234567890123456789012',
                'UNSUPPORTED_VERSION',
            ),
            'Empty type' => array(
                $this->version,
                'INVALID_SIZE',
            ),
            'Unsupported type' => array(
                $this->version . chr(111) . $this->iterationsData . $this->salt . $this->iv .
                $this->encryptAndPadAes('1234567890123456') .
                '12345678901234567890123456789012',
                'UNSUPPORTED_TYPE',
            ),
            'Empty iterations' => array(
                $this->version . $this->type,
                'INVALID_SIZE',
            ),
            'Partial iterations' => array(
                $this->version . $this->type . '123',
                'INVALID_SIZE',
            ),
            'Empty salt' => array(
                $this->version . $this->type . $this->iterationsData,
                'INVALID_SIZE',
            ),
            'Partial salt' => array(
                $this->version . $this->type . $this->iterationsData . '123456789012345678901234567890123456789012345678901234567890123',
                'INVALID_SIZE',
            ),
            'Empty IV' => array(
                $this->version . $this->type . $this->iterationsData . $this->salt,
                'INVALID_SIZE',
            ),
            'Partial IV' => array(
                $this->version . $this->type . $this->iterationsData . $this->salt . '123456789012345',
                'INVALID_SIZE',
            ),
            'Empty data and MAC' => array(
                $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv,
                'INVALID_SIZE',
            ),
            'Empty data' => array(
                $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv .
                '123456789012345678901234567',
                'INVALID_SIZE',
            ),
            'Not enough data for MAC' => array(
                $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv .
                $this->encryptAndPadAes('1234567890123456') . '123456789012345678901234567',
                'INVALID_SIZE',
            ),
            'Invalid data length' => array(
                $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv .
                $this->encryptAes('1234567890123456') . '12' .
                substr($this->encryptAndPadAes('1234567890123456'), 0, 15) . '12' .
                '12345678901234567890123456789012',
                'INVALID_SIZE',
            ),
            'Bad block MAC' => array(
                $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv .
                substr($this->encryptAndPadAes('1234567890123456'), 0, 16) .
                $this->authenticate(substr($this->encryptAndPadAes('1234567890123456'), 0, 16), 2) .
                substr($this->encryptAndPadAes('1234567890123456'), 16) .
                '12' .
                '12345678901234567890123456789012',
                'INVALID_MAC',
            ),
            'Bad MAC' => array(
                $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv .
                substr($this->encryptAndPadAes('1234567890123456'), 0, 16) .
                $this->authenticate(substr($this->encryptAndPadAes('1234567890123456'), 0, 16), 2) .
                substr($this->encryptAndPadAes('1234567890123456'), 16) .
                $this->authenticate(substr($this->encryptAndPadAes('1234567890123456'), 16), 2) .
                '12345678901234567890123456789012',
                'INVALID_MAC',
            ),
            'Bad AES data' => array(
                $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv .
                'foobarbazquxdoom' . $this->authenticate('foobarbazquxdoom', 2) .
                $this->authenticate(
                    $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv . 'foobarbazquxdoom'
                ),
                'INVALID_PADDING',
            ),
            'Bad padding' => array(
                $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv .
                $this->encryptAes('1234567890123456') .
                $this->authenticate($this->encryptAes('1234567890123456'), 2) .
                $this->authenticate(
                    $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv .
                    $this->encryptAes('1234567890123456')
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
        $this->assertNull($result->data());
        $this->assertNull($result->iterations());
        $this->assertNotNull($error);
        $this->assertSame($expected, $error);
        $this->assertSame('', $output);
        $this->assertNull($context);
    }

    public function testTransformFailureAfterSuccessfulBlocks()
    {
        $block = $this->encryptAes('1234567890123456');
        list($output, $buffer, $context, $error) = $this->feedTransform(
            $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv .
            $block . $this->authenticate($block, 2) .
            $block . $this->authenticate($block, 2) .
            $block . $this->authenticate($block, 2) .
            $block . $this->authenticate($block, 2),
            $this->authenticate(
                $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv .
                $block . $block . $block . $block
            )
        );
        $result = $this->transform->result();

        $this->assertNotNull($result);
        $this->assertFalse($result->isSuccessful());
        $this->assertSame('INVALID_PADDING', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertNull($result->iterations());
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
            'sha256',
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
