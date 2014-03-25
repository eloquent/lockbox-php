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

class DocumentationTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->fixturePath = __DIR__ . '/../fixture/key';
    }

    public function testGeneratingKey()
    {
        $this->expectOutputRegex('/^[A-Za-z0-9_=-]{43}$/');

        $keyGenerator = new KeyGenerator;

        $key = $keyGenerator->generateKey();
        echo $key->string(); // outputs the raw key in base64url format
    }

    public function testEncryptingData()
    {
        $this->expectOutputRegex('/^[A-Za-z0-9_=-]{86}$/');

        $data = 'Super secret data.';

        $keyReader = new KeyReader;
        $key = $keyReader->readFile($this->fixturePath . '/key256.lockbox.key');

        $cipher = new EncryptionCipher;
        echo $cipher->encrypt($key, $data);
    }

    public function testEncryptingMultipleData()
    {
        $this->expectOutputRegex('/^[A-Za-z0-9_=-]{258}$/');

        $data = array(
            'Super secret data.',
            'Extra secret data.',
            'Mega secret data.',
        );

        $keyReader = new KeyReader;
        $key = $keyReader->readFile($this->fixturePath . '/key256.lockbox.key');

        $cipher = new BoundEncryptionCipher($key);

        $encrypted = array();
        foreach ($data as $string) {
            echo $cipher->encrypt($string);
        }
    }

    public function testDecryptingData()
    {
        $this->expectOutputString('Super secret data.');

        $encrypted =
            'U9dlhCQHGZR0j79SIu31m9GeNDnvpR-R' .
            'f8q8wp_4wC65kYnCk1FHakcxxFgMgDeK' .
            'cNpn1J6DfIPh_hjqmDw5UA';

        $keyReader = new KeyReader;
        $key = $keyReader->readFile($this->fixturePath . '/key256.lockbox.key');

        $cipher = new DecryptionCipher;

        try {
            $data = $cipher->decrypt($key, $encrypted);
        } catch (DecryptionFailedException $e) {
            // decryption failed
        }

        echo $data;
    }

    public function testDecryptingMultipleData()
    {
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

        $keyReader = new KeyReader;
        $key = $keyReader->readFile($this->fixturePath . '/key256.lockbox.key');

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
