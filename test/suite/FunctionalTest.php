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

        $this->encryptionCipher = Phake::partialMock('Eloquent\Lockbox\EncryptionCipher');
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
                '1234567890123456',
                'MTIzNDU2Nzg5MDEyMzQ1NtitNTFRhW3K' .
                'MfhqusPDqWJ7K37AvEHDaLULPKBNj24c',
            ),

            'Test vector 2' => array(
                256,
                '1234',
                '12345678901234567890123456789012',
                '1234567890123456',
                'MTIzNDU2Nzg5MDEyMzQ1NtwL_JNwnG1u' .
                'T1zKZNgUcr2GaWk31ahOBKB0lfr-E7W2',
            ),

            'Test vector 3' => array(
                256,
                '1234567890123456',
                '12345678901234567890123456789012',
                '1234567890123456',
                'MTIzNDU2Nzg5MDEyMzQ1NnuUZ55SZL-E' .
                'BpxoZDMH74B7GmHK66rSGH0MoSGY1fZC' .
                'hAWyjRKa0nWslBVkLoJRUg',
            ),

            'Test vector 4' => array(
                128,
                '1234567890123456',
                '1234567890123456',
                '1234567890123456',
                'MTIzNDU2Nzg5MDEyMzQ1Nti1mEjHZwyU' .
                'sptU0jeeLnruuN6ZozqGFrUL9qKQprBQ' .
                'wcd0wdNXzvXMY6wYqDwQ4w',
            ),
        );
    }

    /**
     * @dataProvider specVectorData
     */
    public function testSpecVectorsEncryption($bits, $data, $key, $iv, $encrypted)
    {
        Phake::when($this->encryptionCipher)->generateIv()->thenReturn($iv);
        $actual = $this->encryptionCipher->encrypt(new Key($key), $data);

        $this->assertSame($encrypted, $actual);
    }

    /**
     * @dataProvider specVectorData
     */
    public function testSpecVectorsDecryption($bits, $data, $key, $iv, $encrypted)
    {
        $this->assertSame($data, $this->decryptionCipher->decrypt(new Key($key), $encrypted));
    }

    public function testEncryptDecryptWithGeneratedKey()
    {
        $key = $this->keyGenerator->generateKey();
        $encrypted = $this->encryptionCipher->encrypt($key, 'foobar');
        $decrypted = $this->decryptionCipher->decrypt($key, $encrypted);

        $this->assertSame('foobar', $decrypted);
    }
}
