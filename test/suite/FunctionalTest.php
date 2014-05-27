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
use Eloquent\Endec\Endec;
use Eloquent\Lockbox\Cipher\Factory\EncryptCipherFactory;
use Eloquent\Lockbox\Decrypter;
use Eloquent\Lockbox\Encrypter;
use Eloquent\Lockbox\Key\Deriver\KeyDeriver;
use Eloquent\Lockbox\Key\Generator\KeyGenerator;
use Eloquent\Lockbox\Key\Key;
use Eloquent\Lockbox\Key\Persistence\KeyReader;
use Eloquent\Lockbox\Key\Persistence\KeyWriter;
use Eloquent\Lockbox\Lockbox;
use Eloquent\Lockbox\Password\Cipher\Factory\PasswordEncryptCipherFactory;
use Eloquent\Lockbox\Password\Cipher\Parameters\PasswordEncryptParameters;
use Eloquent\Lockbox\Password\Password;
use Eloquent\Lockbox\Password\PasswordDecrypter;
use Eloquent\Lockbox\Password\PasswordEncrypter;
use Eloquent\Lockbox\Password\RawPasswordEncrypter;
use Eloquent\Lockbox\RawEncrypter;

class FunctionalTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->randomSource = Phake::mock('Eloquent\Lockbox\Random\RandomSourceInterface');

        $this->encrypter = new Encrypter(new RawEncrypter(new EncryptCipherFactory($this->randomSource)));
        $this->decrypter = new Decrypter;

        $this->passwordEncrypter = new PasswordEncrypter(
            new RawPasswordEncrypter(
                new PasswordEncryptCipherFactory($this->randomSource, new KeyDeriver($this->randomSource))
            )
        );
        $this->passwordDecrypter = new PasswordDecrypter;

        $this->keyGenerator = new KeyGenerator;
        $this->keyDeriver = new KeyDeriver;

        $this->keyWriter = new KeyWriter;
        $this->keyReader = new KeyReader;

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

                'AQExMjM0NTY3ODkwMTIzNDU2tVIs1T89WnKMXFMUdO_BUPegEaWEA7BxYzH4mJOUjm0pJ-pOUJKNBMsMtSyzM38jogU',
            ),

            'Test vector 2' => array(
                '1234',
                '12345678901234567890123456789012',
                '12345678901234567890123456789013',
                '1234567890123456',

                'AQExMjM0NTY3ODkwMTIzNDU29y1Ry4ScCb8pINaXGcAG6f4aBA_B-YyJdD0eFBRogZ4pxj_5iNuupj5uhSL8yd-AMqs',
            ),

            'Test vector 3' => array(
                '1234567890123456',
                '12345678901234567890123456789012',
                '12345678901234567890123456789013',
                '1234567890123456',

                'AQExMjM0NTY3ODkwMTIzNDU2e5RnnlJkv4QGnGhkMwfvgMCRCp4ZXiiMQpZeiZIVAEJXAdtSP5hbq90deLmjtKIqyzfqm80Sk_vfWKxSPCrdNgqughM',
            ),

            'Test vector 4' => array(
                '1234567890123456',
                '123456789012345678901234',
                '12345678901234567890123456789013',
                '1234567890123456',

                'AQExMjM0NTY3ODkwMTIzNDU2SEo7luYjbf5hHHXCvr7wn2dTt9KMV2gNsmf_hIIobfkilYivNzXWOgsm5ejh0dc9-J1x8qlb2S8VMYUwITKdXxrZRLw',
            ),

            'Test vector 5' => array(
                '1234567890123456',
                '1234567890123456',
                '12345678901234567890123456789013',
                '1234567890123456',

                'AQExMjM0NTY3ODkwMTIzNDU22LWYSMdnDJSym1TSN54uenz7xevJ653uU48K2WlZXXp0DCvfYQ6q5ObK4RuF4DZRXuWSVO2WnhadtRv73h1tDJOClPQ',
            ),

            'Test vector 6' => array(
                '1234567890123456',
                '12345678901234567890123456789012',
                    '12345678901234567890123456789012' .
                '34567890123456789012345678901234',
                '1234567890123456',

                'AQExMjM0NTY3ODkwMTIzNDU2e5RnnlJkv4QGnGhkMwfvgBP8Cp4ZXiiMQpZeiZIVAEJXAfYlRZvB_Cl1sH_pgnnnwz6ojFJ6ZKjpoQfZCoCaM9T-KS3VbIt943GB6Jn6OTdE30eUH1v1k0BsOVt22RC9__2z_w',
            ),

            'Test vector 7' => array(
                '1234567890123456',
                '12345678901234567890123456789012',
                '12345678901234567890123456789012' .
                    '3456789012345678',
                '1234567890123456',

                'AQExMjM0NTY3ODkwMTIzNDU2e5RnnlJkv4QGnGhkMwfvgImRCp4ZXiiMQpZeiZIVAEJXATrAdzCUBzhv8if3P30FXS2KollITdlXpmtV45AqbEJgjZtQg7-KqDxkug-sivc8xux8',
            ),

            'Test vector 8' => array(
                '1234567890123456',
                '12345678901234567890123456789012',
                '1234567890123456789012345678',
                '1234567890123456',

                'AQExMjM0NTY3ODkwMTIzNDU2e5RnnlJkv4QGnGhkMwfvgAYpCp4ZXiiMQpZeiZIVAEJXAeQtUnlfZs7trQgXzSzfNSZuUuxfAx37B2kdkCBcuA',
            ),
        );
    }

    /**
     * @dataProvider specVectorData
     * @large
     */
    public function testSpecVectorsEncryption($data, $encryptSecret, $authSecret, $iv, $encrypted)
    {
        Phake::when($this->randomSource)->generate(16)->thenReturn($iv);
        $actual = $this->encrypter->encrypt(new Key($encryptSecret, $authSecret), $data);

        $this->assertSame($encrypted, $actual);
    }

    /**
     * @dataProvider specVectorData
     * @large
     */
    public function testSpecVectorsEncryptionStreaming($data, $encryptSecret, $authSecret, $iv, $encrypted)
    {
        Phake::when($this->randomSource)->generate(16)->thenReturn($iv);
        $stream = $this->encrypter->createEncryptStream(new Key($encryptSecret, $authSecret));
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
                throw new Exception($error->type()->key());
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
     * @large
     */
    public function testSpecVectorsDecryption($data, $encryptSecret, $authSecret, $iv, $encrypted)
    {
        $result = $this->decrypter->decrypt(new Key($encryptSecret, $authSecret), $encrypted);

        $this->assertTrue($result->isSuccessful());
        $this->assertSame($data, $result->data());
    }

    /**
     * @dataProvider specVectorData
     * @large
     */
    public function testSpecVectorsDecryptionStreaming($data, $encryptSecret, $authSecret, $iv, $encrypted)
    {
        $stream = $this->decrypter->createDecryptStream(new Key($encryptSecret, $authSecret));
        $actual = '';
        $stream->on(
            'data',
            function ($data, $stream) use (&$actual) {
                $actual .= $data;
            }
        );
        $result = null;
        $stream->on(
            'success',
            function ($stream) use (&$result) {
                $result = $stream->result();
            }
        );
        $stream->on(
            'error',
            function ($error, $stream) {
                throw new Exception($error->type()->key());
            }
        );
        foreach (str_split($encrypted) as $byte) {
            $stream->write($byte);
        }
        $stream->end();

        $this->assertNotNull($result);
        $this->assertTrue($result->isSuccessful());
        $this->assertSame($data, $actual);
    }

    /**
     * @large
     */
    public function testEncryptDecryptWithGeneratedKey()
    {
        Phake::when($this->randomSource)->generate(16)->thenReturn(mcrypt_create_iv(16, MCRYPT_DEV_URANDOM));
        $key = $this->keyGenerator->generateKey();
        $encrypted = $this->encrypter->encrypt($key, 'foobar');
        $result = $this->decrypter->decrypt($key, $encrypted);

        $this->assertTrue($result->isSuccessful());
        $this->assertSame('foobar', $result->data());
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

                'AQIAAAPoMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDEyMzQ1Njc4OTAxMjM0NTbKO-iACmwcdh00okIG4I0kdhCbtRwZ6cu21dI6F_7BqxxjCliOhBBwzAIr6qjY2F0TxA',
            ),

            'Test vector 2' => array(
                '1234',
                'password',
                1000,
                '12345678901234567890123456789012' .
                    '34567890123456789012345678901234',
                '1234567890123456',

                'AQIAAAPoMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDEyMzQ1Njc4OTAxMjM0NTYe6N-KqDbnBK8hqAyTEA2GsI_f9suwZRuxDSl9KRuktfiVzlEd2iWyW6QpwSuOzGHUcg',
            ),

            'Test vector 3' => array(
                '1234567890123456',
                'password',
                1000,
                '12345678901234567890123456789012' .
                    '34567890123456789012345678901234',
                '1234567890123456',

                'AQIAAAPoMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDEyMzQ1Njc4OTAxMjM0NTb-18_f5tw1j9guUZtvGVYPVslRN1XLvZRa-z62OCm7lnGwKtkzmQQr9mK6YCAHel1_oahAIGtIjOgxcIRJw0avttztQA',
            ),

            'Test vector 4' => array(
                '1234567890123456',
                'foobar',
                1000,
                '12345678901234567890123456789012' .
                    '34567890123456789012345678901234',
                '1234567890123456',

                'AQIAAAPoMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDEyMzQ1Njc4OTAxMjM0NTa94Xlqf2aIeVQprx_9arAgqeCjjNqHwIgsI2sta80f0VPVX7S3C_4P3ihF1SXv4Oino9rMIKAddiCw3UppnvO936MmNg',
            ),

            'Test vector 5' => array(
                '1234567890123456',
                'password',
                1,
                '12345678901234567890123456789012' .
                    '34567890123456789012345678901234',
                '1234567890123456',

                'AQIAAAABMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDEyMzQ1Njc4OTAxMjM0NTb9vjKl34mezWUWSt8xkFJoeiGVmZSOvJa-7dRTNkE2Zt5Ws-Vy_Di5uA13Im8fbzerspijnlKgYKFQxzfoUjNsC6x3BQ',
            ),

            'Test vector 6' => array(
                '1234567890123456',
                'password',
                100000,
                '12345678901234567890123456789012' .
                    '34567890123456789012345678901234',
                '1234567890123456',

                'AQIAAYagMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDEyMzQ1Njc4OTAxMjM0NTZXSSXsZAg0Ah7ins7upI6063wNxr5xo4VFhDR3QngTIJjUUjZSFAig8llMlHA_swtxsi4-s--UvY284Zzrqrm8vLBU1g',
            ),
        );
    }

    /**
     * @dataProvider passwordSpecVectorData
     * @large
     */
    public function testPasswordSpecVectorsEncryption($data, $password, $iterations, $salt, $iv, $encrypted)
    {
        Phake::when($this->randomSource)->generate(64)->thenReturn($salt);
        Phake::when($this->randomSource)->generate(16)->thenReturn($iv);
        $actual = $this->passwordEncrypter
            ->encrypt(new PasswordEncryptParameters(new Password($password), $iterations), $data);

        $this->assertSame($encrypted, $actual);
    }

    /**
     * @dataProvider passwordSpecVectorData
     * @large
     */
    public function testPasswordSpecVectorsEncryptionStreaming($data, $password, $iterations, $salt, $iv, $encrypted)
    {
        Phake::when($this->randomSource)->generate(64)->thenReturn($salt);
        Phake::when($this->randomSource)->generate(16)->thenReturn($iv);
        $stream = $this->passwordEncrypter
            ->createEncryptStream(new PasswordEncryptParameters(new Password($password), $iterations));
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
                throw new Exception($error->type()->key());
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
     * @large
     */
    public function testPasswordSpecVectorsDecryption($data, $password, $iterations, $salt, $iv, $encrypted)
    {
        $result = $this->passwordDecrypter->decrypt(new Password($password), $encrypted);

        $this->assertTrue($result->isSuccessful());
        $this->assertSame($data, $result->data());
        $this->assertSame($iterations, $result->iterations());
    }

    /**
     * @dataProvider passwordSpecVectorData
     * @large
     */
    public function testPasswordSpecVectorsDecryptionStreaming($data, $password, $iterations, $salt, $iv, $encrypted)
    {
        $stream = $this->passwordDecrypter->createDecryptStream(new Password($password));
        $actual = '';
        $stream->on(
            'data',
            function ($data, $stream) use (&$actual) {
                $actual .= $data;
            }
        );
        $result = null;
        $stream->on(
            'success',
            function ($stream) use (&$result) {
                $result = $stream->result();
            }
        );
        $stream->on(
            'error',
            function ($error, $stream) {
                throw new Exception($error->type()->key());
            }
        );
        foreach (str_split($encrypted) as $byte) {
            $stream->write($byte);
        }
        $stream->end();

        $this->assertNotNull($result);
        $this->assertTrue($result->isSuccessful());
        $this->assertSame($data, $actual);
        $this->assertSame($iterations, $result->iterations());
    }

    /**
     * @large
     */
    public function testEncryptDecryptWithPassword()
    {
        Phake::when($this->randomSource)->generate(16)->thenReturn(mcrypt_create_iv(16, MCRYPT_DEV_URANDOM));
        Phake::when($this->randomSource)->generate(64)->thenReturn(mcrypt_create_iv(64, MCRYPT_DEV_URANDOM));
        $encrypted = $this->passwordEncrypter
            ->encrypt(new PasswordEncryptParameters(new Password('password'), 10), 'foobar');
        $result = $this->passwordDecrypter->decrypt(new Password('password'), $encrypted);

        $this->assertTrue($result->isSuccessful());
        $this->assertSame('foobar', $result->data());
        $this->assertSame(10, $result->iterations());
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
     * @large
     */
    public function testKeyDerivationSpecVectors($password, $iterations, $salt, $encryptSecret, $authSecret)
    {
        list($key) = $this->keyDeriver->deriveKeyFromPassword(new Password($password), $iterations, $salt);

        $this->assertSame($encryptSecret, $this->base64Url->encode($key->encryptSecret()));
        $this->assertSame($authSecret, $this->base64Url->encode($key->authSecret()));
    }

    /**
     * @large
     */
    public function testRealKeyReadWrite()
    {
        $path = sprintf('%s/%s', sys_get_temp_dir(), uniqid('lockbox-'));
        $key = $this->keyReader->readFile(__DIR__ . '/../fixture/key/key-256-256.lockbox.key');
        $this->keyWriter->writeFile($key, $path);
        $actual = $this->keyReader->readFile($path);
        unlink($path);

        $this->assertEquals($key, $actual);
    }

    /**
     * @large
     */
    public function testRealKeyReadWriteEncrypted()
    {
        $path = sprintf('%s/%s', sys_get_temp_dir(), uniqid('lockbox-'));
        $key = $this->keyReader->readFileWithPassword(
            new Password('password'),
            __DIR__ . '/../fixture/key/key-256-256-encrypted.lockbox.key'
        );
        $this->keyWriter
            ->writeFileWithPassword($key, new PasswordEncryptParameters(new Password('password'), 10), $path);
        $actual = $this->keyReader->readFileWithPassword(new Password('password'), $path);
        unlink($path);

        $this->assertEquals($key, $actual);
    }

    /**
     * @large
     */
    public function testRealKeyReadFailure()
    {
        $this->setExpectedException('Eloquent\Lockbox\Key\Persistence\Exception\KeyReadException');
        $this->keyReader->readFile('/path/to/nonexistant');
    }

    /**
     * @large
     */
    public function testRealKeyWriteFailure()
    {
        $key = $this->keyReader->readFile(__DIR__ . '/../fixture/key/key-256-256.lockbox.key');

        $this->setExpectedException('Eloquent\Lockbox\Key\Persistence\Exception\KeyWriteException');
        $this->keyWriter->writeFile($key, '/path/to/nonexistant');
    }

    /**
     * @large
     */
    public function testStreamFilters()
    {
        Lockbox::registerFilters();
        Endec::registerFilters();
        $key = $this->keyReader->readFile(__DIR__ . '/../fixture/key/key-256-256.lockbox.key');
        $path = sprintf('%s/%s', sys_get_temp_dir(), uniqid('lockbox-'));
        $stream = fopen($path, 'wb');
        stream_filter_append($stream, 'lockbox.encrypt', STREAM_FILTER_WRITE, $key);
        stream_filter_append($stream, 'endec.base64url-encode');
        fwrite($stream, 'foobar');
        fclose($stream);
        $stream = fopen($path, 'rb');
        stream_filter_append($stream, 'endec.base64url-decode');
        stream_filter_append($stream, 'lockbox.decrypt', STREAM_FILTER_READ, $key);
        $actual = stream_get_contents($stream);
        fclose($stream);
        unlink($path);

        $this->assertSame('foobar', $actual);
    }

    /**
     * @large
     */
    public function testPasswordStreamFilters()
    {
        Lockbox::registerFilters();
        Endec::registerFilters();
        $password = new Password('password');
        $encryptParameters = new PasswordEncryptParameters($password, 10);
        $path = sprintf('%s/%s', sys_get_temp_dir(), uniqid('lockbox-'));
        $stream = fopen($path, 'wb');
        stream_filter_append($stream, 'lockbox.password-encrypt', STREAM_FILTER_WRITE, $encryptParameters);
        stream_filter_append($stream, 'endec.base64url-encode');
        fwrite($stream, 'foobar');
        fclose($stream);
        $stream = fopen($path, 'rb');
        stream_filter_append($stream, 'endec.base64url-decode');
        stream_filter_append($stream, 'lockbox.password-decrypt', STREAM_FILTER_READ, $password);
        $actual = stream_get_contents($stream);
        fclose($stream);
        unlink($path);

        $this->assertSame('foobar', $actual);
    }
}
