<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

use Eloquent\Lockbox\DecryptionCipher;
use Eloquent\Lockbox\EncryptionCipher;
use Eloquent\Lockbox\Key\Key;
use Eloquent\Lockbox\Key\KeyGenerator;

class FunctionalTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->randomSource = Phake::mock('Eloquent\Lockbox\Random\RandomSourceInterface');
        $this->encryptionCipher = new EncryptionCipher($this->randomSource);
        $this->decryptionCipher = new DecryptionCipher;
        $this->keyGenerator = new KeyGenerator;
    }

    public function specVectorData()
    {
        return array(
            'Test vector 1' => array(
                256,
                '',
                '12345678901234567890123456789012',
                '12345678901234567890123456789013',
                '1234567890123456',
                'MTIzNDU2Nzg5MDEyMzQ1NrVSLNU_PVpy' .
                'jFxTFHTvwVCZ2VlzIBLFCPuEG6E-WkhZ' .
                'VowAdHa17ztnCh0MAw7q6Q',
            ),

            'Test vector 2' => array(
                256,
                '1234',
                '12345678901234567890123456789012',
                '12345678901234567890123456789013',
                '1234567890123456',
                'MTIzNDU2Nzg5MDEyMzQ1NvctUcuEnAm_' .
                'KSDWlxnABunIIK4h2MSoyG7nPL-Qc-ks' .
                'SABFkpUIJI0ERlWRpjERSg',
            ),

            'Test vector 3' => array(
                256,
                '1234567890123456',
                '12345678901234567890123456789012',
                '12345678901234567890123456789013',
                '1234567890123456',
                'MTIzNDU2Nzg5MDEyMzQ1NnuUZ55SZL-E' .
                'BpxoZDMH74AKnhleKIxCll6JkhUAQlcB' .
                'FYF8FIAdi9LUw8iV23vcddM94ZViMoYc' .
                'W3Dle8fXTfo',
            ),

            'Test vector 4' => array(
                128,
                '1234567890123456',
                '1234567890123456',
                '12345678901234567890123456789013',
                '1234567890123456',
                'MTIzNDU2Nzg5MDEyMzQ1Nti1mEjHZwyU' .
                'sptU0jeeLnrF68nrne5TjwrZaVldenQM' .
                'mRuB7XdmN9iFFGFi_hL0l95OadeyfZ6P' .
                'LuVkgPPo13Q',
            ),
        );
    }

    /**
     * @dataProvider specVectorData
     */
    public function testSpecVectorsEncryption($bits, $data, $encryptionSecret, $authenticationSecret, $iv, $encrypted)
    {
        Phake::when($this->randomSource)->generate(16)->thenReturn($iv);
        $actual = $this->encryptionCipher->encrypt(new Key($encryptionSecret, $authenticationSecret), $data);

        $this->assertSame($encrypted, $actual);
    }

    /**
     * @dataProvider specVectorData
     */
    public function testSpecVectorsDecryption($bits, $data, $encryptionSecret, $authenticationSecret, $iv, $encrypted)
    {
        $this->assertSame(
            $data,
            $this->decryptionCipher->decrypt(new Key($encryptionSecret, $authenticationSecret), $encrypted)
        );
    }

    public function testEncryptDecryptWithGeneratedKey()
    {
        Phake::when($this->randomSource)->generate(16)->thenReturn(mcrypt_create_iv(16, MCRYPT_DEV_URANDOM));
        $key = $this->keyGenerator->generateKey();
        $encrypted = $this->encryptionCipher->encrypt($key, 'foobar');
        $decrypted = $this->decryptionCipher->decrypt($key, $encrypted);

        $this->assertSame('foobar', $decrypted);
    }
}
