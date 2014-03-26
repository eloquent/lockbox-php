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
                'jFxTFHTvwVD3oNnoY53lf7Wyt3lRQoq3' .
                'JVgEO4qxrXOoI3hLK-ajPg',
            ),

            'Test vector 2' => array(
                256,
                '1234',
                '12345678901234567890123456789012',
                '12345678901234567890123456789013',
                '1234567890123456',
                'MTIzNDU2Nzg5MDEyMzQ1NvctUcuEnAm_' .
                'KSDWlxnABun-GuM_rdojg1LZx1WtxtMz' .
                'K6L8bG94x0FBmM_tx7Hkkw',
            ),

            'Test vector 3' => array(
                256,
                '1234567890123456',
                '12345678901234567890123456789012',
                '12345678901234567890123456789013',
                '1234567890123456',
                'MTIzNDU2Nzg5MDEyMzQ1NnuUZ55SZL-E' .
                'BpxoZDMH74AKnhleKIxCll6JkhUAQlcB' .
                'ZBbO9U3cEGRu4i9RIGfl0_vL_edhjnsY' .
                '31M9GGEnUdE',
            ),

            'Test vector 4' => array(
                128,
                '1234567890123456',
                '1234567890123456',
                '12345678901234567890123456789013',
                '1234567890123456',
                'MTIzNDU2Nzg5MDEyMzQ1Nti1mEjHZwyU' .
                'sptU0jeeLnrF68nrne5TjwrZaVldenQM' .
                'v7muNqqphAyGko4inI02Omug4lVgv7PR' .
                'S2wFZNQP7vI',
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
