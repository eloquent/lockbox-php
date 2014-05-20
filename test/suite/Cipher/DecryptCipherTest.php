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
use Exception;
use PHPUnit_Framework_TestCase;

class DecryptCipherTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->unpadder = new PkcsPadding;
        $this->resultFactory = new CipherResultFactory;
        $this->cipher = new DecryptCipher($this->unpadder, $this->resultFactory);

        $this->version = $this->type = chr(1);
        $this->parameters = new Key('1234567890123456', '1234567890123456789012345678');
        $this->iv = '1234567890123456';
        $this->encryptParameters = new EncryptParameters($this->parameters, $this->iv);
        $this->encryptCipher = new EncryptCipher;
        $this->base64Url = Base64Url::instance();
    }

    public function testConstructor()
    {
        $this->assertSame($this->unpadder, $this->cipher->unpadder());
        $this->assertSame($this->resultFactory, $this->cipher->resultFactory());
    }

    public function testConstructorDefaults()
    {
        $this->cipher = new DecryptCipher;

        $this->assertSame(PkcsPadding::instance(), $this->cipher->unpadder());
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

        $this->assertSame(118, strlen($encrypted));

        $this->cipher->initialize($this->parameters);
        $output = '';
        $output .= $this->cipher->process(substr($encrypted, 0, 1));   // version
        $output .= $this->cipher->process(substr($encrypted, 1, 1));   // type
        $output .= $this->cipher->process(substr($encrypted, 2, 16));  // IV
        $output .= $this->cipher->process(substr($encrypted, 18, 18)); // block 0
        $output .= $this->cipher->process(substr($encrypted, 36, 18)); // block 1
        $output .= $this->cipher->process(substr($encrypted, 54, 18)); // block 2
        $output .= $this->cipher->process(substr($encrypted, 72, 18)); // padding block
        $output .= $this->cipher->process(substr($encrypted, 90));     // MAC
        $output .= $this->cipher->finalize();
        $result = $this->cipher->result();

        $this->assertTrue($this->cipher->isFinalized());
        $this->assertTrue($this->cipher->hasResult());
        $this->assertSame('SUCCESS', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertSame($input, $output);
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
                $this->version . $this->type . $this->iv . substr($authedBlock, 0, -1) .
                $this->authenticate($this->version . $this->type . $this->iv . substr($block, 0, -1)),
                'INVALID_SIZE',
            ),
            'Unsupported version' => array(
                chr(111) . $this->type . $this->iv . $authedBlock .
                $this->authenticate(chr(111) . $this->type . $this->iv . $block),
                'UNSUPPORTED_VERSION',
            ),
            'Unsupported type' => array(
                $this->version . chr(111) . $this->iv . $authedBlock .
                $this->authenticate($this->version . chr(111) . $this->iv . $block),
                'UNSUPPORTED_TYPE',
            ),
            'Bad block MAC' => array(
                $this->version . $this->type . $this->iv . $block . '12' .
                $this->authenticate($this->version . $this->type . $this->iv . $block),
                'INVALID_MAC',
            ),
            'Bad MAC' => array(
                $this->version . $this->type . $this->iv . $authedBlock . '1234567890123456789012345678',
                'INVALID_MAC',
            ),
            'Bad ciphertext' => array(
                $this->version . $this->type . $this->iv .
                'foobarbazquxdoom' . $this->authenticate('foobarbazquxdoom', 2) .
                $this->authenticate($this->version . $this->type . $this->iv . 'foobarbazquxdoom'),
                'INVALID_PADDING',
            ),
            'Bad padding' => array(
                $this->version . $this->type . $this->iv .
                $unpaddedBlock . $this->authenticate($unpaddedBlock, 2) .
                $this->authenticate($this->version . $this->type . $this->iv . $unpaddedBlock),
                'INVALID_PADDING',
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
        $input = 'foobarbazquxdoomsplat';
        $this->encryptCipher->initialize($this->encryptParameters);
        $encrypted = $this->encryptCipher->finalize($input);
        $this->cipher->initialize(new Key('12345678901234567890123456789012', '12345678901234567890123456789012'));
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
        $input = 'foobarbazquxdoomsplat';
        $this->encryptCipher->initialize($this->encryptParameters);
        $encrypted = $this->encryptCipher->finalize($input);
        $this->cipher->reset();
        $this->cipher->initialize($this->parameters);
        $this->cipher->process($this->version . $this->type . $this->iv);
        $this->cipher->reset();
        $output = $this->cipher->finalize($encrypted);
        $result = $this->cipher->result();

        $this->assertTrue($this->cipher->isFinalized());
        $this->assertTrue($this->cipher->hasResult());
        $this->assertSame('SUCCESS', $result->type()->key());
        $this->assertNull($result->data());
        $this->assertSame($input, $output);
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
        return mcrypt_encrypt(
            MCRYPT_RIJNDAEL_128,
            $this->parameters->encryptSecret(),
            $data,
            MCRYPT_MODE_CBC,
            $this->iv
        );
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
        $mac = hash_hmac(
            'sha' . $this->parameters->authSecretBits(),
            $data,
            $this->parameters->authSecret(),
            true
        );

        if (null !== $size) {
            $mac = substr($mac, 0, $size);
        }

        return $mac;
    }
}
