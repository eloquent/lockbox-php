<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
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
                '',
                '12345678901234567890123456789012',
                '1234567890123456',
                'FzFcxXm57XqDzsZm4vVUaspsK1-Hcw7fN' .
                'jAqadl-WhwR_Kfwv4gM7v7OnDGWfpDOTl' .
                'I_nlQvvwP3TP98tOhyrsJkpDDMZ0WSQVP' .
                'cl23xTk6xbLvwl2qRVdZa8isKCXXcuKt5' .
                'XIv1Mexp2Dzyn8w8TNYOdK0EiNj1v2PUk' .
                '7X2QUPvK0poT_3fUlN13aK28KBqg-CGw0' .
                'xzsGSG4k7CN8FEfGqbSBfuNxumH0eJyzZ' .
                '1s4cYbcn3OWdlQln7asp21WZHj7SEMWIf' .
                'dsrtoWL85uEAnLxYG_CXD1nteVXffAwFv' .
                'ByMT1UmNQ0AWjm8KJiH8hLXPr09rbo5Vz' .
                's6c5lSrjMmM9itNTFRhW3KMfhqusPDqWJ' .
                '7K37AvEHDaLULPKBNj24c'
            ),

            'Test vector 2' => array(
                '1234',
                '12345678901234567890123456789012',
                '1234567890123456',
                'wdPXCy5amuY7U8tGD0M-nnK5LGc4DC1h' .
                'VwvNWVLCyqOMHgDF3fpsY-8MQkMUuI0T' .
                'eNoutU-TpuGsm6D-KIXeAaWIYuUAaNZ-' .
                'V_5WwmRFT5BEyhQwZ3PFybrs39o4sAlO' .
                'd5IVvLNMMgwRD-FmQc8KU10d3KDd71wW' .
                'r50y7R33xTnyJplx9uqcOrB6ooQLjFcF' .
                'bFU87YPnhkxZK5JryTxAlaDJjfFs-3XM' .
                'zgoJ35rpBgDVywPXbye1C8u5gw81awid' .
                'Xgei_a27MZog1lUvETzMXqqZ4VlhckDV' .
                'm71f4TLMKHTz-CmYinvzj7G_pYmvtHeh' .
                'uxDzjdrT4lbetTuESm-YHKtq9JEj6E2S' .
                'ER4TURlVKf14sPeDgRUo88-zvM7BWpMv'
            ),

            'Test vector 3' => array(
                '1234567890123456',
                '12345678901234567890123456789012',
                '1234567890123456',
                'umvbDKEQtKldCN15bgyGyLm5K5LEDNGJ' .
                'kXbyYask_sgSi9lkGa5ByDZKVs1SMgp0' .
                'mif4GDfyg5xVadsPzoH9-jdSoTB7pNxz' .
                'ns8CNP8KIWEcU6TATwjbW9bP5FBQKxRO' .
                'OTHdLLJ7ADqvuT0QxH1Yy1xzlVGXUXxk' .
                'coMBey_CxiboqjLm_cEl1dA0HyidgxTn' .
                'rArsM7porZPj__gbWIEv58L0S2xv11YL' .
                '0IQMGkQiupJhHKiyAIH4KchZ8whV_aAZ' .
                '193U7toEJ7Ojd7uu6hzMiVDCIRPDa5Ek' .
                'zyBFoNsr2hcTFcU4oxBkRbUottvH9Dji' .
                'SxIPU4O8vomXpUqWzneJ4CBlVmSYgUJa' .
                '4zsJUnll4lufFRTYTYjuCgQhunOAIVS2' .
                'DxuQH8bSZZrHKNIghc0D3Q'
            ),
        );
    }

    /**
     * @dataProvider specVectorData
     */
    public function testSpecVectorsEncryption($data, $key, $iv, $encrypted)
    {
        Phake::when($this->encryptionCipher)->generateKey()->thenReturn($key);
        Phake::when($this->encryptionCipher)->generateIv()->thenReturn($iv);
        $expected = substr($encrypted, 342);
        $actual = substr($this->encryptionCipher->encrypt($this->publicKey, $data), 342);

        $this->assertSame($expected, $actual);
    }

    /**
     * @dataProvider specVectorData
     */
    public function testSpecVectorsDecryption($data, $key, $iv, $encrypted)
    {
        $this->assertSame($data, $this->decryptionCipher->decrypt($this->privateKey, $encrypted));
    }

    public function testEncryptingData()
    {
        $data = 'Super secret data.';

        $keyFactory = new KeyFactory;
        $privateKey = $keyFactory->createPrivateKeyFromFile($this->fixturePath . '/rsa-2048.private.pem', 'password');
        $publicKey = $privateKey->publicKey();

        $cipher = new EncryptionCipher;
        $encrypted = $cipher->encrypt($publicKey, $data);

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
        $privateKey = $keyFactory->createPrivateKeyFromFile($this->fixturePath . '/rsa-2048.private.pem', 'password');
        $publicKey = $privateKey->publicKey();

        $cipher = new BoundEncryptionCipher($publicKey);

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
        $privateKey = $keyFactory->createPrivateKeyFromFile($this->fixturePath . '/rsa-2048.private.pem', 'password');

        $cipher = new DecryptionCipher;

        try {
            $data = $cipher->decrypt($privateKey, $encrypted);
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
        $privateKey = $keyFactory->createPrivateKeyFromFile($this->fixturePath . '/rsa-2048.private.pem', 'password');

        $cipher = new BoundDecryptionCipher($privateKey);

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
