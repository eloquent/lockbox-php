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
        $this->expectOutputRegex('/^[A-Za-z0-9_=-]{86}$/');

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
        $this->expectOutputRegex('/^[A-Za-z0-9_=-]{258}$/');

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
            'U9dlhCQHGZR0j79SIu31m9GeNDnvpR-R' .
            'f8q8wp_4wC65kYnCk1FHakcxxFgMgDeK' .
            'cNpn1J6DfIPh_hjqmDw5UA';

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
            'U9dlhCQHGZR0j79SIu31m9GeNDnvpR-R' .
            'f8q8wp_4wC65kYnCk1FHakcxxFgMgDeK' .
            'cNpn1J6DfIPh_hjqmDw5UA',
            'NitEEnhKfkEPLWLQXfulnhe2mjN8bmaY' .
            'sMpNVyPNW9ICHxjV5KHWkomOxQNcxppN' .
            '1JRz4F_xoHLNVcfAhRJD8Q',
            'doIBCztIqSVI8twuMPVPE1CIl-Ql0Ebf' .
            '6dVIsTtDeu-USk5LWAmW7-wlB5kjNNr4' .
            'a-Y9SjtPlF4_OA4qeZV_uA',
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
