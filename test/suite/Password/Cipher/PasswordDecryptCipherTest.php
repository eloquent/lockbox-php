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
use Eloquent\Lockbox\Key\Deriver\KeyDeriver;
use Eloquent\Lockbox\Key\Key;
use Eloquent\Lockbox\Padding\PkcsPadding;
use Eloquent\Lockbox\Password\Cipher\Parameters\PasswordEncryptParameters;
use Eloquent\Lockbox\Password\Cipher\Result\Factory\PasswordDecryptResultFactory;
use Eloquent\Lockbox\Password\Password;
use Exception;
use PHPUnit_Framework_TestCase;

class PasswordDecryptCipherTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->maxIterations = 111;
        $this->keyDeriver = new KeyDeriver;
        $this->unpadder = new PkcsPadding;
        $this->resultFactory = new PasswordDecryptResultFactory;
        $this->cipher = new PasswordDecryptCipher(
            $this->maxIterations,
            $this->keyDeriver,
            $this->unpadder,
            $this->resultFactory
        );

        $this->version = chr(1);
        $this->type = chr(2);
        $this->parameters = new Password('password');
        $this->iterations = 10;
        $this->iterationsData = pack('N', $this->iterations);
        $this->salt = '1234567890123456789012345678901234567890123456789012345678901234';
        $this->iv = '1234567890123456';
        $this->encryptParameters = new PasswordEncryptParameters(
            $this->parameters,
            $this->iterations,
            $this->salt,
            $this->iv
        );
        $this->encryptCipher = new PasswordEncryptCipher;
        $this->base64Url = Base64Url::instance();

        list($this->key) = $this->keyDeriver->deriveKeyFromPassword($this->parameters, $this->iterations, $this->salt);
    }

    public function testConstructor()
    {
        $this->assertSame($this->maxIterations, $this->cipher->maxIterations());
        $this->assertSame($this->keyDeriver, $this->cipher->keyDeriver());
        $this->assertSame($this->unpadder, $this->cipher->unpadder());
        $this->assertSame($this->resultFactory, $this->cipher->resultFactory());
    }

    public function testConstructorDefaults()
    {
        $this->cipher = new PasswordDecryptCipher;

        $this->assertSame(4194304, $this->cipher->maxIterations());
        $this->assertSame(KeyDeriver::instance(), $this->cipher->keyDeriver());
        $this->assertSame(PkcsPadding::instance(), $this->cipher->unpadder());
        $this->assertSame(PasswordDecryptResultFactory::instance(), $this->cipher->resultFactory());
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
        $this->cipher->initialize(new Key('1234567890123456', '1234567890123456789012345678'));
    }

    public function cipherData()
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
     * @dataProvider cipherData
     */
    public function testCipher($input)
    {
        $this->encryptCipher->initialize($this->encryptParameters);
        $encrypted = $this->encryptCipher->finalize($input);
        $this->cipher->initialize($this->parameters);
        $output = $this->cipher->finalize($encrypted);
        $result = $this->cipher->result();

        $this->assertTrue($this->cipher->isFinalized());
        $this->assertTrue($this->cipher->hasResult());
        $this->assertSame('SUCCESS', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertSame($input, $output);
    }

    /**
     * @dataProvider cipherData
     */
    public function testCipherByteByByte($input)
    {
        $this->encryptCipher->initialize($this->encryptParameters);
        $encrypted = $this->encryptCipher->finalize($input);
        $inputSize = strlen($encrypted);
        $this->cipher->initialize($this->parameters);
        $output = '';
        for ($i = 0; $i < $inputSize; $i ++) {
            $output .= $this->cipher->process($encrypted[$i]);
        }
        $output .= $this->cipher->finalize();
        $result = $this->cipher->result();

        $this->assertTrue($this->cipher->isFinalized());
        $this->assertTrue($this->cipher->hasResult());
        $this->assertSame('SUCCESS', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertSame($input, $output);
    }

    public function testCipherWithExactSectionSizes()
    {
        $input = 'foobarbazquxdoomfoobarbazquxdoomfoobarbazquxdoom';
        $this->encryptCipher->initialize($this->encryptParameters);
        $encrypted = $this->encryptCipher->finalize($input);

        $this->assertSame(190, strlen($encrypted));

        $this->cipher->initialize($this->parameters);
        $output = '';
        $output .= $this->cipher->process(substr($encrypted, 0, 1));    // version
        $output .= $this->cipher->process(substr($encrypted, 1, 1));    // type
        $output .= $this->cipher->process(substr($encrypted, 2, 4));    // iterations
        $output .= $this->cipher->process(substr($encrypted, 6, 64));   // salt
        $output .= $this->cipher->process(substr($encrypted, 70, 18));  // IV
        $output .= $this->cipher->process(substr($encrypted, 88, 18));  // block 0
        $output .= $this->cipher->process(substr($encrypted, 106, 18)); // block 1
        $output .= $this->cipher->process(substr($encrypted, 124, 18)); // block 2
        $output .= $this->cipher->process(substr($encrypted, 142, 18)); // padding block
        $output .= $this->cipher->process(substr($encrypted, 160));     // MAC
        $output .= $this->cipher->finalize();
        $result = $this->cipher->result();

        $this->assertTrue($this->cipher->isFinalized());
        $this->assertTrue($this->cipher->hasResult());
        $this->assertSame('SUCCESS', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertSame($input, $output);
    }

    public function testCipherWithEncryptionParameters()
    {
        $this->encryptCipher->initialize($this->encryptParameters);
        $encrypted = $this->encryptCipher->finalize('foobar');
        $this->cipher->initialize($this->encryptParameters);
        $output = $this->cipher->finalize($encrypted);
        $result = $this->cipher->result();

        $this->assertTrue($this->cipher->isFinalized());
        $this->assertTrue($this->cipher->hasResult());
        $this->assertSame('SUCCESS', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertSame('foobar', $output);
    }

    public function testCipherWithMaxIterations()
    {
        $this->encryptParameters = new PasswordEncryptParameters(
            $this->parameters,
            $this->maxIterations,
            $this->salt,
            $this->iv
        );
        $this->encryptCipher->initialize($this->encryptParameters);
        $encrypted = $this->encryptCipher->finalize('foobar');
        $this->cipher->initialize($this->parameters);
        $output = $this->cipher->finalize($encrypted);
        $result = $this->cipher->result();

        $this->assertTrue($this->cipher->isFinalized());
        $this->assertTrue($this->cipher->hasResult());
        $this->assertSame('SUCCESS', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertSame('foobar', $output);
    }

    public function decryptFailureData()
    {
        $this->setUp();

        $block = $this->encryptAndPad('');
        $authedBlock = $block . $this->authenticate($block, 2);
        $unpaddedBlock = $this->encrypt('1234567890123456');

        $data = array(
            'Empty' => array(
                '',
                'INVALID_SIZE',
            ),
            'Insufficient data' => array(
                $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv .
                substr($authedBlock, 0, -1) .
                $this->authenticate(
                    $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv .
                    substr($block, 0, -1)
                ),
                'INVALID_SIZE',
            ),
            'Unsupported version' => array(
                chr(111) . $this->type . $this->iterationsData . $this->salt . $this->iv . $authedBlock .
                $this->authenticate(chr(111) . $this->type . $this->iterationsData . $this->salt . $this->iv . $block),
                'UNSUPPORTED_VERSION',
            ),
            'Unsupported type' => array(
                $this->version . chr(111) . $this->iterationsData . $this->salt . $this->iv . $authedBlock .
                $this->authenticate(
                    $this->version . chr(111) . $this->iterationsData . $this->salt . $this->iv . $block
                ),
                'UNSUPPORTED_TYPE',
            ),
            'Bad block MAC' => array(
                $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv . $block . '12' .
                $this->authenticate(
                    $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv . $block
                ),
                'INVALID_MAC',
            ),
            'Bad MAC' => array(
                $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv . $authedBlock .
                    '12345678901234567890123456789012',
                'INVALID_MAC',
            ),
            'Bad ciphertext' => array(
                $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv .
                'foobarbazquxdoom' . $this->authenticate('foobarbazquxdoom', 2) .
                $this->authenticate(
                    $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv . 'foobarbazquxdoom'
                ),
                'INVALID_PADDING',
            ),
            'Bad padding' => array(
                $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv .
                $unpaddedBlock . $this->authenticate($unpaddedBlock, 2) .
                $this->authenticate(
                    $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv . $unpaddedBlock
                ),
                'INVALID_PADDING',
            ),
            'Too many iterations' => array(
                $this->version . $this->type . pack('N', $this->maxIterations + 1) . $this->salt . $this->iv .
                $authedBlock .
                $this->authenticate(
                    $this->version . $this->type . pack('N', $this->maxIterations + 1) . $this->salt . $this->iv .
                    $block
                ),
                'TOO_MANY_ITERATIONS',
            ),
        );

        foreach ($data as $label => &$row) {
            $row[0] = $this->base64Url->encode($row[0]);
        }

        return $data;
    }

    /**
     * @dataProvider decryptFailureData
     */
    public function testCipherDecryptFailure($input, $expected)
    {
        $input = $this->base64Url->decode($input);
        $this->cipher->initialize($this->parameters);
        $output = $this->cipher->finalize($input);
        $result = $this->cipher->result();

        $this->assertTrue($this->cipher->isFinalized());
        $this->assertTrue($this->cipher->hasResult());
        $this->assertSame($expected, $result->type()->key());
        $this->assertFalse($result->isSuccessful());
        $this->assertNull($result->data());
    }

    /**
     * @dataProvider decryptFailureData
     */
    public function testCipherDecryptFailureByteByByte($input, $expected)
    {
        $input = $this->base64Url->decode($input);
        $inputSize = strlen($input);
        $this->cipher->initialize($this->parameters);
        $output = '';
        for ($i = 0; $i < $inputSize; $i ++) {
            $output .= $this->cipher->process($input[$i]);
        }
        $output .= $this->cipher->finalize();
        $result = $this->cipher->result();

        $this->assertTrue($this->cipher->isFinalized());
        $this->assertTrue($this->cipher->hasResult());
        $this->assertSame($expected, $result->type()->key());
        $this->assertFalse($result->isSuccessful());
        $this->assertNull($result->data());
    }

    public function testInitializeAfterUse()
    {
        $input = $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv . '123456789012345678';
        $this->encryptCipher->initialize($this->encryptParameters);
        $encrypted = $this->encryptCipher->finalize($input);
        $this->cipher->initialize(new Password('foobar'));
        $this->cipher->process($input);
        $this->cipher->initialize($this->parameters);
        $output = $this->cipher->finalize($encrypted);
        $result = $this->cipher->result();

        $this->assertTrue($this->cipher->isFinalized());
        $this->assertTrue($this->cipher->hasResult());
        $this->assertSame('SUCCESS', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertSame($input, $output);
    }

    public function testResetAfterUse()
    {
        $input = $this->version . $this->type . $this->iterationsData . $this->salt . $this->iv . '123456789012345678';
        $this->encryptCipher->initialize($this->encryptParameters);
        $encrypted = $this->encryptCipher->finalize($input);
        $this->cipher->reset();
        $this->cipher->initialize($this->parameters);
        $this->cipher->process($this->version . $this->type . $this->iterationsData . $this->salt . $this->iv);
        $this->cipher->reset();
        $output = $this->cipher->finalize($encrypted);
        $result = $this->cipher->result();

        $this->assertTrue($this->cipher->isFinalized());
        $this->assertTrue($this->cipher->hasResult());
        $this->assertSame('SUCCESS', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertSame($input, $output);
    }

    public function testDeinitialize()
    {
        $this->cipher->initialize($this->parameters);
        $this->cipher->deinitialize();

        $this->assertFalse($this->cipher->isInitialized());
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

    protected function encrypt($data)
    {
        return mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $this->key->encryptSecret(), $data, MCRYPT_MODE_CBC, $this->iv);
    }

    protected function encryptAndPad($data)
    {
        return $this->encrypt($this->pad($data));
    }

    protected function pad($data)
    {
        $padSize = intval(16 - (strlen($data) % 16));

        return $data . str_repeat(chr($padSize), $padSize);
    }

    protected function authenticate($data, $size = null)
    {
        $mac = hash_hmac('sha' . $this->key->authSecretBits(), $data, $this->key->authSecret(), true);

        if (null !== $size) {
            $mac = substr($mac, 0, $size);
        }

        return $mac;
    }
}
