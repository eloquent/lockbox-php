<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

use Eloquent\Lockbox\BoundDecrypter;
use Eloquent\Lockbox\BoundEncrypter;
use Eloquent\Lockbox\Decrypter;
use Eloquent\Lockbox\Encrypter;
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
            '/{"type":"lockbox-key","version":1,' .
            '"encryptionSecret":"[A-Za-z0-9_=-]{43}",' .
            '"authenticationSecret":"[A-Za-z0-9_=-]{43}"}/',
            file_get_contents($keyPath)
        );
    }

    // =========================================================================

    public function testEncryptingData()
    {
        $keyPath = $this->fixturePath . '/key-256-256.lockbox.key';
        $this->expectOutputRegex('/^[A-Za-z0-9_=-]{110}$/');

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
        $this->expectOutputRegex('/^[A-Za-z0-9_=-]{330}$/');

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
    'AQHJqPyMjO0oNSwu1HctzQp9_OQe2tmuQyMWWnetqT-N6vdB9O27NcCyfErbywGhI04N0Cr5CcFiOLHkpn3yTvGravUE8RsvesmvldJU8iIZYw';

try {
    echo $decrypter->decrypt($key, $encrypted);
} catch (DecryptionFailedException $e) {
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

$descrypter = new BoundDecrypter($key);

$encrypted = array(
    'AQHJqPyMjO0oNSwu1HctzQp9_OQe2tmuQyMWWnetqT-N6vdB9O27NcCyfErbywGhI04N0Cr5CcFiOLHkpn3yTvGravUE8RsvesmvldJU8iIZYw',
    'AQHXJbA8N8xITOTGVb7kUVLX0LDIHi4WHIpfOjtGiTvRYOmuXjGdUw7kFAaCrq_ND_HwU69xTYUJTBFpgwHr5hh1jt4AWPLlkGfROKovD6ZoMQ',
    'AQHBx7LoNSXeswYbDzkqE7qoexOOXS-Lu87YERVsggufJ-LItt7ZzU-Lro8gsme9oCDXaduwwM6mKv0vROftOFb-W1fhd7xoIixC7EUC07gIdg',
);

foreach ($encrypted as $string) {
    try {
        echo $descrypter->decrypt($string);
    } catch (DecryptionFailedException $e) {
        echo 'Decryption failed.';
    }
}
    }
}
