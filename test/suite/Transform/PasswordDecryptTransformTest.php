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
use Eloquent\Lockbox\Password\BoundPasswordEncrypter;
use Eloquent\Lockbox\Password\RawPasswordEncrypter;
use Eloquent\Lockbox\Transform\Factory\PasswordEncryptTransformFactory;
use Exception;
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
        $this->transform = new PasswordDecryptTransform($this->password, $this->keyDeriver);

        $this->version = chr(1);
        $this->type = chr(2);
        $this->iterations = 1000;
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
    }

    public function testConstructorDefaults()
    {
        $this->transform = new PasswordDecryptTransform($this->password);

        $this->assertSame(KeyDeriver::instance(), $this->transform->keyDeriver());
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

        $this->assertSame(array($input, '', null), array($output, $buffer, $error));
        $this->assertSame($this->iterations, $this->transform->iterations());
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

        $this->assertSame(array($input, '', null), array($output, $buffer, $error));
        $this->assertSame($this->iterations, $this->transform->iterations());
        $this->assertNull($context);
    }

    public function testTransformWithExactSectionSizes()
    {
        $input = 'foobarbazquxdoomfoobarbazquxdoomfoobarbazquxdoom';
        $encrypted = $this->encrypter->encrypt($input);

        $this->assertSame(182, strlen($encrypted));

        list($output, $buffer, $context, $error) = $this->feedTransform(
            substr($encrypted, 0, 1),    // version
            substr($encrypted, 1, 1),    // type
            substr($encrypted, 2, 4),    // iterations
            substr($encrypted, 6, 64),   // salt
            substr($encrypted, 70, 16),  // IV
            substr($encrypted, 86, 16),  // block 0
            substr($encrypted, 102, 16), // block 1
            substr($encrypted, 118, 16), // block 2
            substr($encrypted, 134, 16), // padding block
            substr($encrypted, 150)      // MAC
        );

        $this->assertSame(array($input, '', null), array($output, $buffer, $error));
        $this->assertSame($this->iterations, $this->transform->iterations());
        $this->assertNull($context);
    }

    public function transformFailureData()
    {
        $this->password = 'password';
        $this->version = chr(1);
        $this->type = chr(2);
        $this->iterations = 1000;
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
            ),
            'Partial version'=> array(
                '1',
            ),
            'Unsupported version' => array(
                chr(111),
            ),
            'Empty type' => array(
                $this->version,
            ),
            'Partial type' => array(
                $this->version . '1',
            ),
            'Unsupported type' => array(
                $this->version . chr(111),
            ),
            'Empty iterations' => array(
                $this->version . $this->type,
            ),
            'Partial iterations' => array(
                $this->version . $this->type . '123',
            ),
            'Empty salt' => array(
                $this->version . $this->type . $this->iterationsData,
            ),
            'Partial salt' => array(
                $this->version . $this->type . $this->iterationsData . '123456789012345678901234567890123456789012345678901234567890123',
            ),
            'Empty IV' => array(
                $this->version . $this->type . $this->iterationsData . $this->salt,
            ),
            'Partial IV' => array(
                $this->version . $this->type . $this->iterationsData . $this->salt . '123456789012345',
            ),
            'Empty data and MAC' => array(
                $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv,
            ),
            'Empty data' => array(
                $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv .
                '123456789012345678901234567',
            ),
            'Not enough data for MAC' => array(
                $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv .
                $this->encryptAndPadAes('1234567890123456') . '123456789012345678901234567',
            ),
            'Invalid data length' => array(
                $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv .
                $this->encryptAes('1234567890123456') .
                substr($this->encryptAndPadAes('1234567890123456'), 0, 15) .
                '1234567890123456789012345678',
            ),
            'Bad MAC' => array(
                $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv .
                $this->encryptAndPadAes('1234567890123456') .
                '1234567890123456789012345678',
            ),
            'Bad AES data' => array(
                $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv . '1234567890123457' .
                $this->authenticationCode(
                    $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv . '1234567890123457'
                ),
            ),
            'Bad padding' => array(
                $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv .
                $this->encryptAes('1234567890123456') .
                $this->authenticationCode(
                    $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv .
                    $this->encryptAes('1234567890123456')
                ),
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
        $this->assertRegExp("/'Eloquent\\\\Lockbox\\\\Exception\\\\PasswordDecryptionFailedException'/", $error);
        $this->assertSame('', $output);
        $this->assertNull($this->transform->iterations());
        $this->assertNull($context);
    }

    public function testTransformFailureAfterSuccessfulBlocks()
    {
        list($output, $buffer, $context, $error) = $this->feedTransform(
            $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv .
                $this->encryptAes('1234567890123456') .
                $this->encryptAes('1234567890123456') .
                $this->encryptAes('1234567890123456') .
                $this->encryptAes('1234567890123456'),
            $this->authenticationCode(
                $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv .
                    $this->encryptAes('1234567890123456') .
                    $this->encryptAes('1234567890123456') .
                    $this->encryptAes('1234567890123456') .
                    $this->encryptAes('1234567890123456')
            )
        );

        $this->assertNotNull($error);
        $this->assertRegExp("/'Eloquent\\\\Lockbox\\\\Exception\\\\PasswordDecryptionFailedException'/", $error);
        $this->assertSame('1234567890123456', $output);
        $this->assertNull($this->transform->iterations());
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
            'sha256',
            $data,
            $this->key->authenticationSecret(),
            true
        );
    }
}
