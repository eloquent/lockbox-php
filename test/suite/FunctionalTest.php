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
                2048,
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
                '7K37AvEHDaLULPKBNj24c',
                342
            ),

            'Test vector 2' => array(
                2048,
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
                'ER4TURlVKf14sPeDgRUo88-zvM7BWpMv',
                342
            ),

            'Test vector 3' => array(
                2048,
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
                'DxuQH8bSZZrHKNIghc0D3Q',
                342
            ),

            'Test vector 4' => array(
                4096,
                '1234567890123456',
                '12345678901234567890123456789012',
                '1234567890123456',
                'XncYhc3C20kG5Zb8VPB0OGBik6N6a6JY' .
                '333Hz6VN3lQ21xMoc16XW0873AzuyvDI' .
                'YAjNzN0pAQo0CosedUptYLLwRtGrsfUr' .
                'XIZxteHNZ7JiEXGZ8W_6bz9jlbnpfNdH' .
                'GxaR-aePTZWSbyPyPdQysGJlqclXJb_K' .
                'dKfqGHLYOf0LO93kvljQ4ccux18vm8PQ' .
                'GIeAH-L5qMfzfOHzcCXbVU746pZf7mNR' .
                'uIEgfp0AM-JEKItYTIZxr8kP7-WlVDf0' .
                '7cjQkZuUEQ7d9FQLKOWviuQ-PQd2enwI' .
                'MYo3btEiu2XHmUcZEcI2esz_vwBGxHNM' .
                'HGrshgpuP_EvPPR_1EogS2EGHs0l_owU' .
                'hHx4V8LvgMBnO3O2nO9p2WA7ZKH1zMZU' .
                'gGaxMAlZrMweaGvEcke2nwnfLUBVytYd' .
                'QNOBV7TmJ3XMXwgpavZ2eKvVXUpdKfcm' .
                'fsGDxjkJRN8BqDTrSZZmSKZe9VZkGSNS' .
                '99jF9BEa6dmy7RTLy3xSaWdPwbElX3pA' .
                'pgQR5BKHz6DP5p86gaQITelAMMYaZQK3' .
                'tNvW6ncRfJGlD3ax_TezCOtrEmlzVCRe' .
                'OsbK51H_xfST_0PO-hXG35NIGC1vDV8r' .
                'iDMr47HbRIFwm9NxT1VR0hDF0LbIIbkS' .
                'YucMkD_Zv9JjoL4FX0rM0T0fvDJBeJXw' .
                'Zt1ifDOvWxogZVZkmIFCWuM7CVJ5ZeJb' .
                'nxUU2E2I7goEIbpzgCFUtg8bkB_G0mWa' .
                'xyjSIIXNA90',
                684
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
