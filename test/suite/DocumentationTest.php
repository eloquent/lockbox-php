<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

use Eloquent\Lockbox\Bound\BoundDecrypter;
use Eloquent\Lockbox\Bound\BoundEncrypter;
use Eloquent\Lockbox\Decrypter;
use Eloquent\Lockbox\Encrypter;
use Eloquent\Lockbox\Key\Generator\KeyGenerator;
use Eloquent\Lockbox\Key\Key;
use Eloquent\Lockbox\Key\Persistence\KeyReader;
use Eloquent\Lockbox\Key\Persistence\KeyWriter;

class DocumentationTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->fixturePath = __DIR__ . '/../fixture/key';
    }

    // =========================================================================

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
            '/{\n    "type": "lockbox-key",\n    "version": 1,\n' .
            '    "encryptSecret": "[A-Za-z0-9_=-]{43}",\n' .
            '    "authSecret": "[A-Za-z0-9_=-]{43}"\n}\n/',
            file_get_contents($keyPath)
        );
    }

    // =========================================================================

    public function testEncryptingData()
    {
        $keyPath = $this->fixturePath . '/key-256-256.lockbox.key';
        $this->expectOutputRegex('/^[A-Za-z0-9_=-]{115}$/');

// $keyPath = '/path/to/lockbox.key';
$keyReader = new KeyReader;
$key = $keyReader->readFile($keyPath);

$encrypter = new Encrypter;
echo $encrypter->encrypt($key, 'Super secret data.');
    }

    // =========================================================================

    public function testEncryptingMultipleData()
    {
        $keyPath = $this->fixturePath . '/key-256-256.lockbox.key';
        $this->expectOutputRegex('/^[A-Za-z0-9_=-]{345}$/');

// $keyPath = '/path/to/lockbox.key';
$keyReader = new KeyReader;
$key = $keyReader->readFile($keyPath);

$encrypter = new BoundEncrypter($key);

echo $encrypter->encrypt('Super secret data.');
echo $encrypter->encrypt('Extra secret data.');
echo $encrypter->encrypt('Mega secret data.');
    }

    // =========================================================================

    public function testDecryptingData()
    {
        $keyPath = $this->fixturePath . '/key-256-256.lockbox.key';
        $this->expectOutputString('Super secret data.');

// $keyPath = '/path/to/lockbox.key';
$keyReader = new KeyReader;
$key = $keyReader->readFile($keyPath);

$decrypter = new Decrypter;

$encrypted =
    'AQF_VjJS9sAL75uuUP_HTu9Do_3itIDaHLLXmh_JLOBRqQeZ_hnDwht4WtEkz3ioiW0WIHb3lANyKqpShyiPcVdj_DbfYiIPEWab8e3vqwEUvoqFFNo';

$result = $decrypter->decrypt($key, $encrypted);
if ($result->isSuccessful()) {
    echo $result->data();
} else {
    echo 'Decryption failed.';
}
    }

    // =========================================================================

    public function testDecryptingMultipleData()
    {
        $keyPath = $this->fixturePath . '/key-256-256.lockbox.key';
        $this->expectOutputString('Super secret data.Extra secret data.Mega secret data.');

// $keyPath = '/path/to/lockbox.key';
$keyReader = new KeyReader;
$key = $keyReader->readFile($keyPath);

$decrypter = new BoundDecrypter($key);

$encrypted = array(
    'AQF_VjJS9sAL75uuUP_HTu9Do_3itIDaHLLXmh_JLOBRqQeZ_hnDwht4WtEkz3ioiW0WIHb3lANyKqpShyiPcVdj_DbfYiIPEWab8e3vqwEUvoqFFNo',
    'AQH44yTs7va1cDoBpX0xVLqIRow5fs8Jj5-DYDJ1R3YY9udBCexmvDs9BH1qJDjCRSqcGriKi_UkL5per1WHwdxWuPq8QsYiBqeC9e9zypl0Xi1QT3s',
    'AQGg0MsYtH0Rboyqssivssupb_GKlBotCpdFtc6WpnMaji8_ZvmGUTRu2DKkxFhAdk_s0FWZ7NYFjSDt1puIrr7MlB7owNuR5KhUIj04Can0zDCYjJY',
);

foreach ($encrypted as $string) {
    $result = $decrypter->decrypt($string);
    if ($result->isSuccessful()) {
        echo $result->data();
    } else {
        echo 'Decryption failed.';
    }
}
    }
}
