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
use Eloquent\Lockbox\Transform\Factory\EncryptTransformFactory;

class FunctionalTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->randomSource = Phake::mock('Eloquent\Lockbox\Random\RandomSourceInterface');
        $this->encrypter = new Encrypter(new RawEncrypter(new EncryptTransformFactory($this->randomSource)));
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

                'AQExMjM0NTY3ODkwMTIzNDU2tVIs1T89WnKMXFMUdO_BUBGlhAOwcWMx-JiTlI5tKSfqTlCSjQTLDLUsszN_I6IF',
            ),

            'Test vector 2' => array(
                '1234',
                '12345678901234567890123456789012',
                '12345678901234567890123456789013',
                '1234567890123456',

                'AQExMjM0NTY3ODkwMTIzNDU29y1Ry4ScCb8pINaXGcAG6QQPwfmMiXQ9HhQUaIGeKcY_-YjbrqY-boUi_MnfgDKr',
            ),

            'Test vector 3' => array(
                '1234567890123456',
                '12345678901234567890123456789012',
                '12345678901234567890123456789013',
                '1234567890123456',

                'AQExMjM0NTY3ODkwMTIzNDU2e5RnnlJkv4QGnGhkMwfvgAqeGV4ojEKWXomSFQBCVwE_mFur3R14uaO0oirLN-qbzRKT-99YrFI8Kt02Cq6CEw',
            ),

            'Test vector 4' => array(
                '1234567890123456',
                '123456789012345678901234',
                '12345678901234567890123456789013',
                '1234567890123456',

                'AQExMjM0NTY3ODkwMTIzNDU2SEo7luYjbf5hHHXCvr7wn7fSjFdoDbJn_4SCKG35IpU3NdY6Cybl6OHR1z34nXHyqVvZLxUxhTAhMp1fGtlEvA',
            ),

            'Test vector 5' => array(
                '1234567890123456',
                '1234567890123456',
                '12345678901234567890123456789013',
                '1234567890123456',

                'AQExMjM0NTY3ODkwMTIzNDU22LWYSMdnDJSym1TSN54uesXryeud7lOPCtlpWV16dAxhDqrk5srhG4XgNlFe5ZJU7ZaeFp21G_veHW0Mk4KU9A',
            ),

            'Test vector 6' => array(
                '1234567890123456',
                '12345678901234567890123456789012',
                    '12345678901234567890123456789012' .
                '34567890123456789012345678901234',
                '1234567890123456',

                'AQExMjM0NTY3ODkwMTIzNDU2e5RnnlJkv4QGnGhkMwfvgAqeGV4ojEKWXomSFQBCVwFFm8H8KXWwf-mCeefDPqiMUnpkqOmhB9kKgJoz1P4pLdVsi33jcYHomfo5N0TfR5QfW_WTQGw5W3bZEL3__bP_',
            ),

            'Test vector 7' => array(
                '1234567890123456',
                '12345678901234567890123456789012',
                '12345678901234567890123456789012' .
                    '3456789012345678',
                '1234567890123456',

                'AQExMjM0NTY3ODkwMTIzNDU2e5RnnlJkv4QGnGhkMwfvgAqeGV4ojEKWXomSFQBCVwF3MJQHOG_yJ_c_fQVdLYqiWUhN2Vema1XjkCpsQmCNm1CDv4qoPGS6D6yK9zzG7Hw',
            ),

            'Test vector 8' => array(
                '1234567890123456',
                '12345678901234567890123456789012',
                '1234567890123456789012345678',
                '1234567890123456',

                'AQExMjM0NTY3ODkwMTIzNDU2e5RnnlJkv4QGnGhkMwfvgAqeGV4ojEKWXomSFQBCVwFSeV9mzu2tCBfNLN81Jm5S7F8DHfsHaR2QIFy4',
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
