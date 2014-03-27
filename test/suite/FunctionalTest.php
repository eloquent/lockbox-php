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
use Eloquent\Lockbox\RawEncrypter;

class FunctionalTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->randomSource = Phake::mock('Eloquent\Lockbox\Random\RandomSourceInterface');
        $this->encrypter = new Encrypter(new RawEncrypter($this->randomSource));
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

                'AAExMjM0NTY3ODkwMTIzNDU2tVIs1T89' .
                'WnKMXFMUdO_BUPeo9JuMx3aiuatDDMe0' .
                'iue5_ehrGCm0ProwqCx16kZJ',
            ),

            'Test vector 2' => array(
                '1234',
                '12345678901234567890123456789012',
                '12345678901234567890123456789013',
                '1234567890123456',

                'AAExMjM0NTY3ODkwMTIzNDU29y1Ry4Sc' .
                'Cb8pINaXGcAG6U9axIQMaJEoIe8_zxvm' .
                'g2vuoXc3Tg0maoz3mQGODQtc',
            ),

            'Test vector 3' => array(
                '1234567890123456',
                '12345678901234567890123456789012',
                '12345678901234567890123456789013',
                '1234567890123456',

                'AAExMjM0NTY3ODkwMTIzNDU2e5RnnlJk' .
                'v4QGnGhkMwfvgAqeGV4ojEKWXomSFQBC' .
                'VwEqcEdby5GlIEgkvlWa0Ff00WY7P2zE' .
                'jB2yclVKwoKaAw',
            ),

            'Test vector 4' => array(
                '1234567890123456',
                '123456789012345678901234',
                '12345678901234567890123456789013',
                '1234567890123456',

                'AAExMjM0NTY3ODkwMTIzNDU2SEo7luYj' .
                'bf5hHHXCvr7wn7fSjFdoDbJn_4SCKG35' .
                'IpVVhI7njUSPKLNGvuu99ZxtkrC0aIuV' .
                '2uFZ-OMLZHJHIw',
            ),

            'Test vector 5' => array(
                '1234567890123456',
                '1234567890123456',
                '12345678901234567890123456789013',
                '1234567890123456',

                'AAExMjM0NTY3ODkwMTIzNDU22LWYSMdn' .
                'DJSym1TSN54uesXryeud7lOPCtlpWV16' .
                'dAx28oTCncYuU0BcwM4JjM8-PR7Sa5cs' .
                '8YIiABzOTbhvkQ',
            ),

            'Test vector 6' => array(
                '1234567890123456',
                '12345678901234567890123456789012',
                    '12345678901234567890123456789012' .
                '34567890123456789012345678901234',
                '1234567890123456',

                'AAExMjM0NTY3ODkwMTIzNDU2e5RnnlJk' .
                'v4QGnGhkMwfvgAqeGV4ojEKWXomSFQBC' .
                'VwG-8pLkxZH8wlE7GsoOLRBJPmX6nWg4' .
                'JJM2qeTRjD4FdfewbHWgqXVtFHjJ0EZH' .
                '85jvZbu5y05tCiUj-5Evr3T2',
            ),

            'Test vector 7' => array(
                '1234567890123456',
                '12345678901234567890123456789012',
                '12345678901234567890123456789012' .
                    '3456789012345678',
                '1234567890123456',

                'AAExMjM0NTY3ODkwMTIzNDU2e5RnnlJk' .
                'v4QGnGhkMwfvgAqeGV4ojEKWXomSFQBC' .
                'VwGlu578TYU_VrM2HhoqJXyxgXXce-A4' .
                'MCGmXsizUtBo7DROW0v_tzrNTgU9jt_1' .
                'QuI',
            ),

            'Test vector 8' => array(
                '1234567890123456',
                '12345678901234567890123456789012',
                '1234567890123456789012345678',
                '1234567890123456',

                'AAExMjM0NTY3ODkwMTIzNDU2e5RnnlJk' .
                'v4QGnGhkMwfvgAqeGV4ojEKWXomSFQBC' .
                'VwGbnuQoFA1fEcvOcTiqg9iTiOOVfRI6' .
                '1Y86f03F',
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
