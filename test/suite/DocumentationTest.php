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
use Eloquent\Lockbox\Key\Key;
use Eloquent\Lockbox\Key\KeyGenerator;
use Eloquent\Lockbox\Key\KeyReader;
use Eloquent\Lockbox\Key\KeyWriter;

class DocumentationTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->fixturePath = __DIR__ . '/../fixture/key';
    }

    public function testGeneratingAndWritingKey()
    {
        $keyPath = sprintf('%s/%s', sys_get_temp_dir(), uniqid('lockbox-'));
        $this->expectOutputString('');

        $keyGenerator = new KeyGenerator;
        $key = $keyGenerator->generateKey();

        // $keyPath = '/path/to/lockbox.key';
        $keyWriter = new KeyWriter;
        $keyWriter->writeFile($key, $keyPath);

        $this->assertRegExp(
            '/{"type":"lockbox-key","version":1,' .
            '"encryptionSecret":"[A-Za-z0-9_=-]{43}",' .
            '"authenticationSecret":"[A-Za-z0-9_=-]{43}"}/',
            file_get_contents($keyPath)
        );
    }

    public function testEncryptingData()
    {
        $keyPath = $this->fixturePath . '/key256.lockbox.key';
        $this->expectOutputRegex('/^[A-Za-z0-9_=-]{107}$/');

        $data = 'Super secret data.';

        // $keyPath = '/path/to/lockbox.key';
        $keyReader = new KeyReader;
        $key = $keyReader->readFile($keyPath);

        $cipher = new EncryptionCipher;
        echo $cipher->encrypt($key, $data);
    }

    public function testEncryptingMultipleData()
    {
        $keyPath = $this->fixturePath . '/key256.lockbox.key';
        $this->expectOutputRegex('/^[A-Za-z0-9_=-]{321}$/');

        $data = array(
            'Super secret data.',
            'Extra secret data.',
            'Mega secret data.',
        );

        // $keyPath = '/path/to/lockbox.key';
        $keyReader = new KeyReader;
        $key = $keyReader->readFile($keyPath);

        $cipher = new BoundEncryptionCipher($key);

        $encrypted = array();
        foreach ($data as $string) {
            echo $cipher->encrypt($string);
        }
    }

    public function testDecryptingData()
    {
        $keyPath = $this->fixturePath . '/key256.lockbox.key';
        $this->expectOutputString('Super secret data.');

        $encrypted =
            '2TkRH_mVR3eID5heNErkHJhJ5kiGyKNG' .
            'UOd41GS5LCzAVvJUVeDi_Rbs0pVbUus2' .
            'i8CTI0Sr0tt5cdPKvuxF9k2gJETEk6KE' .
            't1T63Cl4pxo';

        // $keyPath = '/path/to/lockbox.key';
        $keyReader = new KeyReader;
        $key = $keyReader->readFile($keyPath);

        $cipher = new DecryptionCipher;

        try {
            $data = $cipher->decrypt($key, $encrypted);
        } catch (DecryptionFailedException $e) {
            echo 'Decryption failed.';
        }

        echo $data;
    }

    public function testDecryptingMultipleData()
    {
        $keyPath = $this->fixturePath . '/key256.lockbox.key';
        $this->expectOutputString('');

        $encrypted = array(
            '2TkRH_mVR3eID5heNErkHJhJ5kiGyKNG' .
            'UOd41GS5LCzAVvJUVeDi_Rbs0pVbUus2' .
            'i8CTI0Sr0tt5cdPKvuxF9k2gJETEk6KE' .
            't1T63Cl4pxo',
            'aNkLcTqavI9aXJ6sCzgIdki9FtgxWu22' .
            'mRmRcw3MMY6wKA1hzunGX1o9KzwerYQp' .
            'iX-RQb62Bwl9xjxUnl_nRdOepB9zatNc' .
            'k2E_m2jvWXI',
            'V0wpEJUP6ZSvgqiz0hw27j-6FqH74b2l' .
            'Ss48ohbR8kQ3LpNa-Gi5PBW1ZR_p8RN9' .
            '3YFtRQYcguxQl7bFAJhb6Y_5jz_8zRUM' .
            'tOZ0rNZlDpI',
        );

        // $keyPath = '/path/to/lockbox.key';
        $keyReader = new KeyReader;
        $key = $keyReader->readFile($keyPath);

        $cipher = new BoundDecryptionCipher($key);

        foreach ($encrypted as $string) {
            try {
                $data = $cipher->decrypt($string);
            } catch (DecryptionFailedException $e) {
            echo 'Decryption failed.';
            }
        }
    }
}
