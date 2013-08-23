<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Eloquent\Lockbox\Key\KeyFactory;

class FunctionalTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->encryptionCipher = Phake::partialMock(
            'Eloquent\Lockbox\EncryptionCipher'
        );
        $this->decryptionCipher = Phake::partialMock(
            'Eloquent\Lockbox\DecryptionCipher'
        );

        $this->keyFactory = new KeyFactory;
        $this->privateKey = $this->keyFactory->createPrivateKeyFromFile(
            __DIR__ . '/../fixture/pem/rsa-2048-nopass.private.pem'
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
}
