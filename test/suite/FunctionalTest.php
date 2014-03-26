<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

use Eloquent\Lockbox\Decrypter;
use Eloquent\Lockbox\Encrypter;
use Eloquent\Lockbox\Key\Key;
use Eloquent\Lockbox\Key\KeyGenerator;

class FunctionalTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->randomSource = Phake::mock('Eloquent\Lockbox\Random\RandomSourceInterface');
        $this->encrypter = new Encrypter($this->randomSource);
        $this->decrypter = new Decrypter;
        $this->keyGenerator = new KeyGenerator;
    }

    public function specVectorData()
    {
        return array(
            'Test vector 1' => array(
                '',
                '12345678901234567890123456789012',
                '12345678901234567890123456789013',
                '1234567890123456',
                'MTIzNDU2Nzg5MDEyMzQ1NrVSLNU_PVpy' .
                'jFxTFHTvwVCZ2VlzIBLFCPuEG6E-WkhZ' .
                'VowAdHa17ztnCh0MAw7q6Q',
            ),

            'Test vector 2' => array(
                '1234',
                '12345678901234567890123456789012',
                '12345678901234567890123456789013',
                '1234567890123456',
                'MTIzNDU2Nzg5MDEyMzQ1NvctUcuEnAm_' .
                'KSDWlxnABunIIK4h2MSoyG7nPL-Qc-ks' .
                'SABFkpUIJI0ERlWRpjERSg',
            ),

            'Test vector 3' => array(
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
                '1234567890123456',
                '123456789012345678901234',
                '12345678901234567890123456789013',
                '1234567890123456',

                'MTIzNDU2Nzg5MDEyMzQ1NkhKO5bmI23-' .
                'YRx1wr6-8J-30oxXaA2yZ_-Egiht-SKV' .
                '0CtvXa04MwkOxkDjlA4Oop-50tb9l_Wh' .
                '1ntB1Zx-4gk',
            ),

            'Test vector 5' => array(
                '1234567890123456',
                '1234567890123456',
                '12345678901234567890123456789013',
                '1234567890123456',

                'MTIzNDU2Nzg5MDEyMzQ1Nti1mEjHZwyU' .
                'sptU0jeeLnrF68nrne5TjwrZaVldenQM' .
                'mRuB7XdmN9iFFGFi_hL0l95OadeyfZ6P' .
                'LuVkgPPo13Q',
            ),

            'Test vector 6' => array(
                '1234567890123456',
                '12345678901234567890123456789012',
                    '12345678901234567890123456789012' .
                '34567890123456789012345678901234',
                '1234567890123456',

                'MTIzNDU2Nzg5MDEyMzQ1NnuUZ55SZL-E' .
                'BpxoZDMH74AKnhleKIxCll6JkhUAQlcB' .
                'gUc25HiivS3hpIWbLzCvuFdkI-4sgBZS' .
                'p-3HZt0nFhzGFfz4-70bsyeWZN2gR4RM' .
                'z23HAP9Q_ka1KDRoMtLQ5w',
            ),

            'Test vector 7' => array(
                '1234567890123456',
                '12345678901234567890123456789012',
                '12345678901234567890123456789012' .
                    '3456789012345678',
                '1234567890123456',

                'MTIzNDU2Nzg5MDEyMzQ1NnuUZ55SZL-E' .
                'BpxoZDMH74AKnhleKIxCll6JkhUAQlcB' .
                'ElWEyH4a6MlRryABUmm7uS_bhk8a-_j8' .
                'yX1uUexmwFl1RxBWzLG1vU7zRGcV0AIX',
            ),

            'Test vector 8' => array(
                '1234567890123456',
                '12345678901234567890123456789012',
                '1234567890123456789012345678',
                '1234567890123456',

                'MTIzNDU2Nzg5MDEyMzQ1NnuUZ55SZL-E' .
                'BpxoZDMH74AKnhleKIxCll6JkhUAQlcB' .
                'Gi15pKq0CYglpHxptwC5qyuqmfjxu179' .
                'GwA9kQ',
            ),
        );
    }

    /**
     * @dataProvider specVectorData
     */
    public function testSpecVectorsEncryption($data, $encryptionSecret, $authenticationSecret, $iv, $encrypted)
    {
        Phake::when($this->randomSource)->generate(16)->thenReturn($iv);
        $actual = $this->encrypter->encrypt(new Key($encryptionSecret, $authenticationSecret), $data);

        $this->assertSame($encrypted, $actual);
    }

    /**
     * @dataProvider specVectorData
     */
    public function testSpecVectorsDecryption($data, $encryptionSecret, $authenticationSecret, $iv, $encrypted)
    {
        $this->assertSame(
            $data,
            $this->decrypter->decrypt(new Key($encryptionSecret, $authenticationSecret), $encrypted)
        );
    }

    public function testEncryptDecryptWithGeneratedKey()
    {
        Phake::when($this->randomSource)->generate(16)->thenReturn(mcrypt_create_iv(16, MCRYPT_DEV_URANDOM));
        $key = $this->keyGenerator->generateKey();
        $encrypted = $this->encrypter->encrypt($key, 'foobar');
        $decrypted = $this->decrypter->decrypt($key, $encrypted);

        $this->assertSame('foobar', $decrypted);
    }
}
