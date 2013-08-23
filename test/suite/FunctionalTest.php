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
        $this->decryptionCipher = Phake::partialMock('Eloquent\Lockbox\DecryptionCipher');

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
                '1234',
                '12345678901234567890123456789012',
                '1234567890123456',
                'E737-vERr-QWfApBhllwqBpVXMMBqTBg' .
                'yMk1F9jh663iyz5nQlgQX_SHsEk6Ga7c' .
                'ZAS059kTdF9t9re24qts68UjMqGivwVU' .
                'IuP_wwPTCFvRHz5fuaU8lqjENZZs9vAn' .
                'LJlm58nZiNit4aBoM9LHXw9djHCojE6b' .
                'lrFL0qS8-p3CE1rXlvT8nN8afFrVNAdn' .
                'yAIY2lbTdiZzPP6tyTf2NLYbB7WahVxG' .
                '-06NHp31wYmPURK1EbP3DE89IX0opOWq' .
                'J6MBGjzUZhtknp3gKoWQNGNVJEwzmgaZ' .
                'BS8m71hO3yuFqoeMDZeZ1liNFAb8uaIQ' .
                'D9SgRrwWJqfsXXF2H3Jzeqtq9JEj6E2S' .
                'ER4TURlVKf14sPeDgRUo88-zvM7BWpMv'
            ),

            'Test vector 2' => array(
                '1234567890123456',
                '12345678901234567890123456789012',
                '1234567890123456',
                'jJTdLagcU1e3NYGKdaj2_vuTJgD8ukC-' .
                'ImPA9_2gcDIamh5LEpKF-VVhyZ891tqy' .
                'FDjfr0yBOD-fQTr47AFmnqV2GT1FfHUx' .
                'fPyiIFKxXrNQ05z-KDkAIySxKCkR52M1' .
                '0gs7Pf9LzzQRNdQHHIz9TF3sMBJ47-Mc' .
                'kPEWjyu3wlJ0XkcMdJxXjgGOBBaAEvo9' .
                '0wYJyeiosYLB7gxoyMmXpkxpNa22fV_t' .
                'HzNWTvYRlKkDv-dqFsElDTv1pBSAXWCV' .
                'whEmpmjJPe5uu84wGPx6lF9hxW7WiEu8' .
                'lRWobJqSnA9QNFbw1xc6W6uNN1Pn7gzS' .
                '28dON8xkrg15R04ok9GNgSBlVmSYgUJa' .
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
