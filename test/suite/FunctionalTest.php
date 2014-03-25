<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

use Eloquent\Lockbox\BoundDecryptionCipher;
use Eloquent\Lockbox\BoundEncryptionCipher;
use Eloquent\Lockbox\DecryptionCipher;
use Eloquent\Lockbox\EncryptionCipher;
use Eloquent\Lockbox\Exception\DecryptionFailedException;
use Eloquent\Lockbox\Key\KeyFactory;

class FunctionalTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->encryptionCipher = Phake::partialMock('Eloquent\Lockbox\EncryptionCipher');
        $this->decryptionCipher = new DecryptionCipher;

        $this->fixturePath = __DIR__ . '/../fixture/pem';
        $this->keyFactory = new KeyFactory;
        $this->privateKey = $this->keyFactory->createPrivateKeyFromFile(
            $this->fixturePath . '/rsa-2048-nopass.private.pem'
        );
        $this->publicKey = $this->privateKey->publicKey();
    }

    public function specVectorData()
    {
        return array(
            'Test vector 1' => array(
                2048,
                '',
                '12345678901234567890123456789012',
                '1234567890123456',
                'QJyn73i2dlN_V9o2fVLLmh4U85AIEL5v' .
                'Cch2sP5aw3CogMBn5qRpokg6OFjRxsYB' .
                'xb_Oqe8n9GALxJsuuqyZgWXxSK0exA2P' .
                'QnAECIcujG9EyM4GlQodJiJdMtDJh0Dd' .
                'frp7s87w7YWgleaK_3JVqEpjRolj1AWr' .
                'DjXeFDl_tGIZ1R95PD2mbq6OUgm1Q56M' .
                'CRLZdZJOm3yixcGHQOV2wv73YIbOvOa8' .
                'hEZ7ydX-VRHPMmJyFgUe9gv8G8sDm6xY' .
                'UEz1rIu62XwMoMB4B3UZo_r0Q9xCr4sx' .
                'BVPY7bOAp6AUjOuvsHwBGJQHZi3k665w' .
                'mShg7pw8HFkr_Fea4nzimditNTFRhW3K' .
                'MfhqusPDqWJ7K37AvEHDaLULPKBNj24c',
                342,
            ),

            'Test vector 2' => array(
                2048,
                '1234',
                '12345678901234567890123456789012',
                '1234567890123456',
                'MFq4hhLJN8_F6ODUWX20tO4RIJURlMHA' .
                'mdujFMTyqc2Y3zHIXzmaK4CcoThggqZX' .
                '44-4kbhjwk9ihwuzS4GAQuSCCdoh5xzT' .
                'WfeboPu6zE51BrZQdz67VavvmvpHVdGg' .
                'oQcSsa_GiZcc7aBYh-AhfCyHrPb-r1hN' .
                'y_AWXv8hcO8mIS1fJ3Mvtr3Xxfwlydrn' .
                '23YUwuOG-tX4FctKqh2eFFkrht53ZwVv' .
                '7q67U3x774KjbUpB4LbML6APxe4ucghl' .
                'DpY_A_DFLH2GlvvouVaT3jCibkY_yIMC' .
                '1lNSBIdgpKGoAoZWy4bIpqDUu0SiLvDO' .
                'mclpPRARakRr15F21a_MQ9wL_JNwnG1u' .
                'T1zKZNgUcr2GaWk31ahOBKB0lfr-E7W2',
                342,
            ),

            'Test vector 3' => array(
                2048,
                '1234567890123456',
                '12345678901234567890123456789012',
                '1234567890123456',
                'oFqfBVNvWyUYThQiA54V_Lpx6Ka2zqEF' .
                'QCQBxcYhnbG2uuShACbf3I31USwRCFDV' .
                'mBLmfcO4ReMJFQzen-tRRuapOQ4Pjzdp' .
                'IRw_T9wYjj0n3Sjs1NZnDbN3hbHCmXoq' .
                'sl0byi0Lr5hwhmqOCj7Po5ey4EsPpuqb' .
                'tPx38PPae-zOlnMrdYuKhV8jIMDSsslf' .
                'VWMOgUlYnDOt9Pd1NEJkJE-GxYIYyzPB' .
                '_NtxwQf5moDjsNzxtx5fzEejo8BGDQ5Q' .
                'phjkQCBmMWd1fKN3Z3aBSNn_WS2HwxzU' .
                'gl10lzaHityP9iZU2DY8qkQB_wSk7-pf' .
                'h05CITq0DPIOHDQzVkcWlnuUZ55SZL-E' .
                'BpxoZDMH74B7GmHK66rSGH0MoSGY1fZC' .
                'hAWyjRKa0nWslBVkLoJRUg',
                342,
            ),

            'Test vector 4' => array(
                4096,
                '1234567890123456',
                '12345678901234567890123456789012',
                '1234567890123456',
                'rqA8g_yyA0eeLoun6rqnUxgy3JnIS9p8' .
                'bAgZYf4774ZahHcFCOozwWbMU_0HVMS9' .
                'sOlAmr-dQl6RqDaOLfAxrHq3mluFSlXf' .
                'gcJXrvPtf27u_4NCHXuwm825ptpmprPx' .
                'wl0z4tz6u-fqNBSfQuHApZ3MvAGsEa0v' .
                'b0IftBX0q8tKL6sdCx6WpTGcynEdxLcZ' .
                'Tx6cM4LRdcjL3SQZ5vk4VF69lS2r1WgJ' .
                'h8eUa_VwgsqhTkoc7wJAECqxHBQSh6q-' .
                'GOt6bpVnlaGkM_BfcrB5SJdtcEZd5BgG' .
                'xG8QwQGwsT60jErxpd5rYLfBrG7kgVse' .
                'yksfN-99-kUHQpkwCIS_zS5bpr3hLpBi' .
                'UhSA4638Xgd2qyAZCgl3OBY56HSdncZq' .
                '5o4xGycM69eN5hb-c852W-dP6S49BXSn' .
                '3OpmEOkZoIeNw0EYHpLLpfaLwafIVdLC' .
                'bQZX1g_szDcBDyyM-PN5-jnuaqySRywF' .
                'rMj56U9vAvwtFMaHKY-ll4Qxf8PgoDWM' .
                '7KogGgkztlZ0ZzaMwBLQeTDpjbNl5NXJ' .
                'CxobJfGv8w6zQZmDz8J2K3DsQrDmZid_' .
                'W6Gtsv7XsSnY-gl6TD4IkK1VEKnttqXa' .
                'PfVdCNadtQ-Z1INiK2pa3F0NKs4POO-K' .
                'PpW68kQ5l2qeUAVv6B-QdcwunyMh9XO_' .
                'vGx8Wf8SrbZ7lGeeUmS_hAacaGQzB--A' .
                'exphyuuq0hh9DKEhmNX2QoQFso0SmtJ1' .
                'rJQVZC6CUVI',
                684,
            ),
        );
    }

    /**
     * @dataProvider specVectorData
     */
    public function testSpecVectorsEncryption($bits, $data, $key, $iv, $encrypted, $rsaLength)
    {
        $this->privateKey = $this->keyFactory->createPrivateKeyFromFile(
            sprintf('%s/rsa-%s-nopass.private.pem', $this->fixturePath, $bits)
        );
        $this->publicKey = $this->privateKey->publicKey();
        Phake::when($this->encryptionCipher)->generateKey()->thenReturn($key);
        Phake::when($this->encryptionCipher)->generateIv()->thenReturn($iv);
        $actual = $this->encryptionCipher->encrypt($this->publicKey, $data);
        $actual = substr($actual, $rsaLength);
        $expected = substr($encrypted, $rsaLength);

        $this->assertSame($expected, $actual);
    }

    /**
     * @dataProvider specVectorData
     */
    public function testSpecVectorsDecryption($bits, $data, $key, $iv, $encrypted, $rsaLength)
    {
        $this->privateKey = $this->keyFactory->createPrivateKeyFromFile(
            sprintf('%s/rsa-%s-nopass.private.pem', $this->fixturePath, $bits)
        );

        $this->assertSame($data, $this->decryptionCipher->decrypt($this->privateKey, $encrypted));
    }

    public function testEncryptDecryptWithGeneratedKey()
    {
        $this->privateKey = $this->keyFactory->generatePrivateKey();
        $encrypted = $this->encryptionCipher->encrypt($this->privateKey, 'foobar');
        $decrypted = $this->decryptionCipher->decrypt($this->privateKey, $encrypted);

        $this->assertSame('foobar', $decrypted);
    }

    public function testGeneratingKey()
    {
        $keyFactory = new KeyFactory;

        $privateKey = $keyFactory->generatePrivateKey();
        /* echo */ $privateKey->string(); // outputs the key in PEM format
        /* echo */ $privateKey->string('password'); // outputs the key in encrypted PEM format

        $publicKey = $privateKey->publicKey();
        /* echo */ $publicKey->string(); // outputs the key in PEM format

        $this->assertTrue(true);
    }

    public function testEncryptingData()
    {
        $data = 'Super secret data.';

        $keyFactory = new KeyFactory;
        $key = $keyFactory->createPrivateKeyFromFile($this->fixturePath . '/rsa-2048.private.pem', 'password');

        $cipher = new EncryptionCipher;
        $encrypted = $cipher->encrypt($key, $data);

        $this->assertTrue(true);
    }

    public function testEncryptingMultipleData()
    {
        $data = array(
            'Super secret data.',
            'Extra secret data.',
            'Mega secret data.',
        );

        $keyFactory = new KeyFactory;
        $key = $keyFactory->createPrivateKeyFromFile($this->fixturePath . '/rsa-2048.private.pem', 'password');

        $cipher = new BoundEncryptionCipher($key);

        $encrypted = array();
        foreach ($data as $string) {
            $encrypted[] = $cipher->encrypt($string);
        }

        $this->assertTrue(true);
    }

    public function testDecryptingData()
    {
        $encrypted = '<some encrypted data>';

        $keyFactory = new KeyFactory;
        $key = $keyFactory->createPrivateKeyFromFile($this->fixturePath . '/rsa-2048.private.pem', 'password');

        $cipher = new DecryptionCipher;

        try {
            $data = $cipher->decrypt($key, $encrypted);
        } catch (DecryptionFailedException $e) {
            // decryption failed
        }

        $this->assertTrue(true);
    }

    public function testDecryptingMultipleData()
    {
        $encrypted = array(
            '<some encrypted data>',
            '<more encrypted data>',
            '<other encrypted data>',
        );

        $keyFactory = new KeyFactory;
        $key = $keyFactory->createPrivateKeyFromFile($this->fixturePath . '/rsa-2048.private.pem', 'password');

        $cipher = new BoundDecryptionCipher($key);

        foreach ($encrypted as $string) {
            try {
                $data = $cipher->decrypt($string);
            } catch (DecryptionFailedException $e) {
                // decryption failed
            }
        }

        $this->assertTrue(true);
    }
}
