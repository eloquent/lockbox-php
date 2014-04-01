<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

use Eloquent\Endec\Base64\Base64Url;
use Eloquent\Lockbox\Decrypter;
use Eloquent\Lockbox\Encrypter;
use Eloquent\Lockbox\Key\Key;
use Eloquent\Lockbox\Key\KeyDeriver;
use Eloquent\Lockbox\Key\KeyGenerator;
use Eloquent\Lockbox\Password\PasswordDecrypter;
use Eloquent\Lockbox\Password\PasswordEncrypter;
use Eloquent\Lockbox\Transform\Factory\EncryptTransformFactory;
use Eloquent\Lockbox\Transform\Factory\PasswordEncryptTransformFactory;

class FunctionalTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->randomSource = Phake::mock('Eloquent\Lockbox\Random\RandomSourceInterface');

        $this->encrypter = new Encrypter(new EncryptTransformFactory($this->randomSource));
        $this->decrypter = new Decrypter;

        $this->passwordEncrypter = new PasswordEncrypter(
            new PasswordEncryptTransformFactory(new KeyDeriver(null, $this->randomSource), $this->randomSource)
        );
        $this->passwordDecrypter = new PasswordDecrypter;

        $this->keyGenerator = new KeyGenerator;
        $this->keyDeriver = new KeyDeriver;

        $this->base64Url = Base64Url::instance();
    }

    public function specVectorData()
    {
        return array(
            'Test vector 1' => array(
                '',
                '12345678901234567890123456789012',
                '12345678901234567890123456789013',
                '1234567890123456',

                'AQExMjM0NTY3ODkwMTIzNDU2tVIs1T89' .
                'WnKMXFMUdO_BUBGlhAOwcWMx-JiTlI5t' .
                'KSfqTlCSjQTLDLUsszN_I6IF',
            ),

            'Test vector 2' => array(
                '1234',
                '12345678901234567890123456789012',
                '12345678901234567890123456789013',
                '1234567890123456',

                'AQExMjM0NTY3ODkwMTIzNDU29y1Ry4Sc' .
                'Cb8pINaXGcAG6QQPwfmMiXQ9HhQUaIGe' .
                'KcY_-YjbrqY-boUi_MnfgDKr',
            ),

            'Test vector 3' => array(
                '1234567890123456',
                '12345678901234567890123456789012',
                '12345678901234567890123456789013',
                '1234567890123456',

                'AQExMjM0NTY3ODkwMTIzNDU2e5RnnlJk' .
                'v4QGnGhkMwfvgAqeGV4ojEKWXomSFQBC' .
                'VwE_mFur3R14uaO0oirLN-qbzRKT-99Y' .
                'rFI8Kt02Cq6CEw',
            ),

            'Test vector 4' => array(
                '1234567890123456',
                '123456789012345678901234',
                '12345678901234567890123456789013',
                '1234567890123456',

                'AQExMjM0NTY3ODkwMTIzNDU2SEo7luYj' .
                'bf5hHHXCvr7wn7fSjFdoDbJn_4SCKG35' .
                'IpU3NdY6Cybl6OHR1z34nXHyqVvZLxUx' .
                'hTAhMp1fGtlEvA',
            ),

            'Test vector 5' => array(
                '1234567890123456',
                '1234567890123456',
                '12345678901234567890123456789013',
                '1234567890123456',

                'AQExMjM0NTY3ODkwMTIzNDU22LWYSMdn' .
                'DJSym1TSN54uesXryeud7lOPCtlpWV16' .
                'dAxhDqrk5srhG4XgNlFe5ZJU7ZaeFp21' .
                'G_veHW0Mk4KU9A',
            ),

            'Test vector 6' => array(
                '1234567890123456',
                '12345678901234567890123456789012',
                    '12345678901234567890123456789012' .
                '34567890123456789012345678901234',
                '1234567890123456',

                'AQExMjM0NTY3ODkwMTIzNDU2e5RnnlJk' .
                'v4QGnGhkMwfvgAqeGV4ojEKWXomSFQBC' .
                'VwFFm8H8KXWwf-mCeefDPqiMUnpkqOmh' .
                'B9kKgJoz1P4pLdVsi33jcYHomfo5N0Tf' .
                'R5QfW_WTQGw5W3bZEL3__bP_',
            ),

            'Test vector 7' => array(
                '1234567890123456',
                '12345678901234567890123456789012',
                '12345678901234567890123456789012' .
                    '3456789012345678',
                '1234567890123456',

                'AQExMjM0NTY3ODkwMTIzNDU2e5RnnlJk' .
                'v4QGnGhkMwfvgAqeGV4ojEKWXomSFQBC' .
                'VwF3MJQHOG_yJ_c_fQVdLYqiWUhN2Vem' .
                'a1XjkCpsQmCNm1CDv4qoPGS6D6yK9zzG' .
                '7Hw',
            ),

            'Test vector 8' => array(
                '1234567890123456',
                '12345678901234567890123456789012',
                '1234567890123456789012345678',
                '1234567890123456',

                'AQExMjM0NTY3ODkwMTIzNDU2e5RnnlJk' .
                'v4QGnGhkMwfvgAqeGV4ojEKWXomSFQBC' .
                'VwFSeV9mzu2tCBfNLN81Jm5S7F8DHfsH' .
                'aR2QIFy4',
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
    public function testSpecVectorsEncryptionStreaming($data, $encryptionSecret, $authenticationSecret, $iv, $encrypted)
    {
        Phake::when($this->randomSource)->generate(16)->thenReturn($iv);
        $stream = $this->encrypter->createEncryptStream(new Key($encryptionSecret, $authenticationSecret));
        $actual = '';
        $stream->on(
            'data',
            function ($data, $stream) use (&$actual) {
                $actual .= $data;
            }
        );
        $stream->on(
            'error',
            function ($error, $stream) {
                throw $error;
            }
        );
        foreach (str_split($data) as $byte) {
            $stream->write($byte);
        }
        $stream->end();

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

    /**
     * @dataProvider specVectorData
     */
    public function testSpecVectorsDecryptionStreaming($data, $encryptionSecret, $authenticationSecret, $iv, $encrypted)
    {
        $stream = $this->decrypter->createDecryptStream(new Key($encryptionSecret, $authenticationSecret));
        $actual = '';
        $stream->on(
            'data',
            function ($data, $stream) use (&$actual) {
                $actual .= $data;
            }
        );
        $stream->on(
            'error',
            function ($error, $stream) {
                throw $error;
            }
        );
        foreach (str_split($encrypted) as $byte) {
            $stream->write($byte);
        }
        $stream->end();

        $this->assertSame($data, $actual);
    }

    public function testEncryptDecryptWithGeneratedKey()
    {
        Phake::when($this->randomSource)->generate(16)->thenReturn(mcrypt_create_iv(16, MCRYPT_DEV_URANDOM));
        $key = $this->keyGenerator->generateKey();
        $encrypted = $this->encrypter->encrypt($key, 'foobar');
        $decrypted = $this->decrypter->decrypt($key, $encrypted);

        $this->assertSame('foobar', $decrypted);
    }

    public function passwordSpecVectorData()
    {
        return array(
            'Test vector 1' => array(
                '',
                'password',
                1000,
                '12345678901234567890123456789012' .
                    '34567890123456789012345678901234',
                '1234567890123456',

                'AQIAAAPoMTIzNDU2Nzg5MDEyMzQ1Njc4' .
                'OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEy' .
                'MzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDEy' .
                'MzQ1Njc4OTAxMjM0NTbKO-iACmwcdh00' .
                'okIG4I0km7UcGenLttXSOhf-wascYwpY' .
                'joQQcMwCK-qo2NhdE8Q',
            ),

            'Test vector 2' => array(
                '1234',
                'password',
                1000,
                '12345678901234567890123456789012' .
                    '34567890123456789012345678901234',
                '1234567890123456',

                'AQIAAAPoMTIzNDU2Nzg5MDEyMzQ1Njc4' .
                'OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEy' .
                'MzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDEy' .
                'MzQ1Njc4OTAxMjM0NTYe6N-KqDbnBK8h' .
                'qAyTEA2G3_bLsGUbsQ0pfSkbpLX4lc5R' .
                'HdolslukKcErjsxh1HI',
            ),

            'Test vector 3' => array(
                '1234567890123456',
                'password',
                1000,
                '12345678901234567890123456789012' .
                    '34567890123456789012345678901234',
                '1234567890123456',

                'AQIAAAPoMTIzNDU2Nzg5MDEyMzQ1Njc4' .
                'OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEy' .
                'MzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDEy' .
                'MzQ1Njc4OTAxMjM0NTb-18_f5tw1j9gu' .
                'UZtvGVYPUTdVy72UWvs-tjgpu5ZxsDOZ' .
                'BCv2YrpgIAd6XX-hqEAga0iM6DFwhEnD' .
                'Rq-23O1A',
            ),

            'Test vector 4' => array(
                '1234567890123456',
                'foobar',
                1000,
                '12345678901234567890123456789012' .
                    '34567890123456789012345678901234',
                '1234567890123456',

                'AQIAAAPoMTIzNDU2Nzg5MDEyMzQ1Njc4' .
                'OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEy' .
                'MzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDEy' .
                'MzQ1Njc4OTAxMjM0NTa94Xlqf2aIeVQp' .
                'rx_9arAgo4zah8CILCNrLWvNH9FT1bcL' .
                '_g_eKEXVJe_g6Kej2swgoB12ILDdSmme' .
                '873foyY2',
            ),

            'Test vector 5' => array(
                '1234567890123456',
                'password',
                1,
                '12345678901234567890123456789012' .
                    '34567890123456789012345678901234',
                '1234567890123456',

                'AQIAAAABMTIzNDU2Nzg5MDEyMzQ1Njc4' .
                'OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEy' .
                'MzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDEy' .
                'MzQ1Njc4OTAxMjM0NTb9vjKl34mezWUW' .
                'St8xkFJolZmUjryWvu3UUzZBNmbeVnL8' .
                'OLm4DXcibx9vN6uymKOeUqBgoVDHN-hS' .
                'M2wLrHcF',
            ),

            'Test vector 6' => array(
                '1234567890123456',
                'password',
                100000,
                '12345678901234567890123456789012' .
                    '34567890123456789012345678901234',
                '1234567890123456',

                'AQIAAYagMTIzNDU2Nzg5MDEyMzQ1Njc4' .
                'OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEy' .
                'MzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDEy' .
                'MzQ1Njc4OTAxMjM0NTZXSSXsZAg0Ah7i' .
                'ns7upI60Dca-caOFRYQ0d0J4EyCY1FIU' .
                'CKDyWUyUcD-zC3GyLj6z75S9jbzhnOuq' .
                'uby8sFTW',
            ),
        );
    }

    /**
     * @dataProvider passwordSpecVectorData
     */
    public function testPasswordSpecVectorsEncryption($data, $password, $iterations, $salt, $iv, $encrypted)
    {
        Phake::when($this->randomSource)->generate(16)->thenReturn($iv);
        Phake::when($this->randomSource)->generate(64)->thenReturn($salt);
        $actual = $this->passwordEncrypter->encrypt($password, $iterations, $data);

        $this->assertSame($encrypted, $actual);
    }

    /**
     * @dataProvider passwordSpecVectorData
     */
    public function testPasswordSpecVectorsEncryptionStreaming($data, $password, $iterations, $salt, $iv, $encrypted)
    {
        Phake::when($this->randomSource)->generate(16)->thenReturn($iv);
        Phake::when($this->randomSource)->generate(64)->thenReturn($salt);
        $stream = $this->passwordEncrypter->createEncryptStream($password, $iterations);
        $actual = '';
        $stream->on(
            'data',
            function ($data, $stream) use (&$actual) {
                $actual .= $data;
            }
        );
        $stream->on(
            'error',
            function ($error, $stream) {
                throw $error;
            }
        );
        foreach (str_split($data) as $byte) {
            $stream->write($byte);
        }
        $stream->end();

        $this->assertSame($encrypted, $actual);
    }

    /**
     * @dataProvider passwordSpecVectorData
     */
    public function testPasswordSpecVectorsDecryption($data, $password, $iterations, $salt, $iv, $encrypted)
    {
        $this->assertSame(array($data, $iterations), $this->passwordDecrypter->decrypt($password, $encrypted));
    }

    /**
     * @dataProvider passwordSpecVectorData
     */
    public function testPasswordSpecVectorsDecryptionStreaming($data, $password, $iterations, $salt, $iv, $encrypted)
    {
        $stream = $this->passwordDecrypter->createDecryptStream($password);
        $actual = '';
        $stream->on(
            'data',
            function ($data, $stream) use (&$actual) {
                $actual .= $data;
            }
        );
        $actualIterations = null;
        $stream->on(
            'success',
            function ($stream) use (&$actualIterations) {
                $transforms = $stream->transform()->transforms();
                $actualIterations = $transforms[1]->iterations();
            }
        );
        $stream->on(
            'error',
            function ($error, $stream) {
                throw $error;
            }
        );
        foreach (str_split($encrypted) as $byte) {
            $stream->write($byte);
        }
        $stream->end();

        $this->assertSame(array($data, $iterations), array($actual, $actualIterations));
    }

    public function testEncryptDecryptWithPassword()
    {
        Phake::when($this->randomSource)->generate(16)->thenReturn(mcrypt_create_iv(16, MCRYPT_DEV_URANDOM));
        Phake::when($this->randomSource)->generate(64)->thenReturn(mcrypt_create_iv(64, MCRYPT_DEV_URANDOM));
        $encrypted = $this->passwordEncrypter->encrypt('password', 10, 'foobar');
        $decrypted = $this->passwordDecrypter->decrypt('password', $encrypted);

        $this->assertSame(array('foobar', 10), $decrypted);
    }

    public function keyDerivationSpecVectorData()
    {
        return array(
            'Test vector 1' => array(
                '',
                1000,
                '12345678901234567890123456789012' .
                '34567890123456789012345678901234',

                '2k1fkksUHSjVMxOMNkPBihtocgu1ziAI' .
                '4CVRFfC7ClM',
                'lNXoGLA83xvvlAUuHCQEw9OcsUloYygz' .
                '2Oq4PFRMUh4'
            ),

            'Test vector 2' => array(
                'foo',
                1000,
                '12345678901234567890123456789012' .
                '34567890123456789012345678901234',

                '9eWWednk0FFnvE_NXA0uElPqBvSRDxTN' .
                'NfKjj8j-w74',
                'H8-n0cCupLeoCYckdGFWlwWc8GAl_XvB' .
                'okZMgWbhB1U'
            ),

            'Test vector 3' => array(
                'foobar',
                1000,
                '12345678901234567890123456789012' .
                '34567890123456789012345678901234',

                'gvP8UROn7oLyZpbguWlDryCE82uANmVH' .
                'dp4cV1ZKNik',
                'shiABRhWtR0nKk6uO_efWMf6yk7iZ8On' .
                'D9PjIdYJxVQ'
            ),

            'Test vector 4' => array(
                'foobar',
                10000,
                '12345678901234567890123456789012' .
                '34567890123456789012345678901234',

                'ZYRW2br9KSzOY4KKpoEGHMXzT4PYa_CP' .
                '5qPdqSkZKXI',
                'Bq2Yqmr9iwi89x-DV5MUIMUmvEAXgYNh' .
                'uLR0dt10jv0'
            ),

            'Test vector 5' => array(
                'foobar',
                100000,
                '12345678901234567890123456789012' .
                '34567890123456789012345678901234',

                'Zbz3tZJjWJDGwMmer1aY1TNBW3uscUCz' .
                'iUpIpAF9sXw',
                'pS5s8iWZBHwzf_hIIm4SMsR9dTHo2yfl' .
                '2WHpa1Fp6wc'
            ),

            'Test vector 6' => array(
                'foobar',
                1,
                '12345678901234567890123456789012' .
                '34567890123456789012345678901234',

                'nrmJyhdG9gAbFrTidwKwg5xeKBFF11wk' .
                'MkJVbVsWG6A',
                'cclAcqBRCzX8VMT-DkiNzHiH4emz6GT_' .
                'iVVpIB84ccw'
            ),
        );
    }

    /**
     * @dataProvider keyDerivationSpecVectorData
     */
    public function testKeyDerivationSpecVectors(
        $password,
        $iterations,
        $salt,
        $expectedEncryptionSecret,
        $expectedAuthenticationSecret
    ) {
        list($key) = $this->keyDeriver->deriveKeyFromPassword($password, $iterations, $salt);

        $this->assertSame($expectedEncryptionSecret, $this->base64Url->encode($key->encryptionSecret()));
        $this->assertSame($expectedAuthenticationSecret, $this->base64Url->encode($key->authenticationSecret()));
    }
}
