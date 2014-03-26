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
        $this->expectOutputRegex('/^[A-Za-z0-9_=-]{107}$/');

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
        $this->expectOutputRegex('/^[A-Za-z0-9_=-]{321}$/');

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
    '37ms0z6MyzvE49o2-cfAJ6sqs3FhqV9uyCOmMOV6qGbM_kVym0R5akGTdCCqUPh7' .
    'la2HrFDcN8Sce7G_5JEgZndnYezCi8ORi-jB-zS9KIc';

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
    '37ms0z6MyzvE49o2-cfAJ6sqs3FhqV9uyCOmMOV6qGbM_kVym0R5akGTdCCqUPh7' .
    'la2HrFDcN8Sce7G_5JEgZndnYezCi8ORi-jB-zS9KIc',
    'a-6y2yEe-yVPM5om7BIQK3nJHgvNJbazvR0gQj3xPgBoR_mDEdFSU9Xt7Ea1EpZB' .
    'eopzBRnP5OdiTZQ76RVV7xZ4-Ym1qRzSJ-JPtdMI7Zo',
    'sxLpTbj1ilbw48M721J-Mb492lShhbDLlRQcp54UTzGRUdHd_8OlKFkIea51b1sq' .
    'k16JtnZqaXxHQCThmdE1pBTWvhQNOCK2XPizrdSTLf0',
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
