<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Key;

use Eloquent\Endec\Base64\Base64Url;
use Eloquent\Liberator\Liberator;
use Eloquent\Lockbox\Random\DevUrandom;
use PHPUnit_Framework_TestCase;
use Phake;

class KeyDeriverTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->factory = new KeyFactory;
        $this->randomSource = Phake::mock('Eloquent\Lockbox\Random\RandomSourceInterface');
        $this->deriver = new KeyDeriver($this->factory, $this->randomSource);

        $this->base64Url = Base64Url::instance();
        $this->salt = '1234567890123456789012345678901234567890123456789012345678901234';
    }

    public function testConstructor()
    {
        $this->assertSame($this->factory, $this->deriver->factory());
        $this->assertSame($this->randomSource, $this->deriver->randomSource());
    }

    public function testConstructorDefaults()
    {
        $this->deriver = new KeyDeriver;

        $this->assertSame(KeyFactory::instance(), $this->deriver->factory());
        $this->assertSame(DevUrandom::instance(), $this->deriver->randomSource());
    }

    public function keyDerivationData()
    {
        $this->salt = '1234567890123456789012345678901234567890123456789012345678901234';

        //                           password  iterations salt         encryptionSecret                               authenticationSecret
        return array(
            'Test vector 1' => array('',       1000,      $this->salt, '2k1fkksUHSjVMxOMNkPBihtocgu1ziAI4CVRFfC7ClM', 'lNXoGLA83xvvlAUuHCQEw9OcsUloYygz2Oq4PFRMUh4'),
            'Test vector 2' => array('foo',    1000,      $this->salt, '9eWWednk0FFnvE_NXA0uElPqBvSRDxTNNfKjj8j-w74', 'H8-n0cCupLeoCYckdGFWlwWc8GAl_XvBokZMgWbhB1U'),
            'Test vector 3' => array('foobar', 1000,      $this->salt, 'gvP8UROn7oLyZpbguWlDryCE82uANmVHdp4cV1ZKNik', 'shiABRhWtR0nKk6uO_efWMf6yk7iZ8OnD9PjIdYJxVQ'),
            'Test vector 4' => array('foobar', 10000,     $this->salt, 'ZYRW2br9KSzOY4KKpoEGHMXzT4PYa_CP5qPdqSkZKXI', 'Bq2Yqmr9iwi89x-DV5MUIMUmvEAXgYNhuLR0dt10jv0'),
            'Test vector 5' => array('foobar', 100000,    $this->salt, 'Zbz3tZJjWJDGwMmer1aY1TNBW3uscUCziUpIpAF9sXw', 'pS5s8iWZBHwzf_hIIm4SMsR9dTHo2yfl2WHpa1Fp6wc'),
            'Test vector 6' => array('foobar', 1,         $this->salt, 'nrmJyhdG9gAbFrTidwKwg5xeKBFF11wkMkJVbVsWG6A', 'cclAcqBRCzX8VMT-DkiNzHiH4emz6GT_iVVpIB84ccw'),
        );
    }

    /**
     * @dataProvider keyDerivationData
     */
    public function testDeriveKeyFromPassword(
        $password,
        $iterations,
        $salt,
        $expectedEncryptionSecret,
        $expectedAuthenticationSecret
    ) {
        list($key) = $this->deriver->deriveKeyFromPassword($password, $iterations, $salt, 'name', 'description');

        $this->assertSame($expectedEncryptionSecret, $this->base64Url->encode($key->encryptionSecret()));
        $this->assertSame($expectedAuthenticationSecret, $this->base64Url->encode($key->authenticationSecret()));
        $this->assertSame('name', $key->name());
        $this->assertSame('description', $key->description());
    }

    public function testDeriveKeyFromPasswordDefaults()
    {
        Phake::when($this->randomSource)->generate(64)->thenReturn($this->salt);
        list($key, $salt) = $this->deriver->deriveKeyFromPassword('foobar', 10);

        $this->assertSame('pcVNTpc-PE-kn5dDsuK6UDMQXXJmAQpOygkGavbvTXE', $this->base64Url->encode($key->encryptionSecret()));
        $this->assertSame('1HoCzL6MzfPLCUXIkCdNrQT4v7vpjltxDGbT2qTLqZk', $this->base64Url->encode($key->authenticationSecret()));
        $this->assertNull($key->name());
        $this->assertNull($key->description());
    }

    public function testDeriveKeyFromPasswordFailureNonStringPassword()
    {
        $this->setExpectedException('Eloquent\Lockbox\Key\Exception\InvalidPasswordException');
        $this->deriver->deriveKeyFromPassword(null, 10);
    }

    public function testDeriveKeyFromPasswordFailureNonIntegerIterations()
    {
        $this->setExpectedException('Eloquent\Lockbox\Key\Exception\InvalidIterationsException');
        $this->deriver->deriveKeyFromPassword('foobar', null);
    }

    public function testDeriveKeyFromPasswordFailureIterationsLessThanOne()
    {
        $this->setExpectedException('Eloquent\Lockbox\Key\Exception\InvalidIterationsException');
        $this->deriver->deriveKeyFromPassword('foobar', 0);
    }

    public function testDeriveKeyFromPasswordFailureNonStringSalt()
    {
        $this->setExpectedException('Eloquent\Lockbox\Key\Exception\InvalidSaltException');
        $this->deriver->deriveKeyFromPassword('foobar', 10, 111);
    }

    public function testDeriveKeyFromPasswordFailureSaltSize()
    {
        $this->setExpectedException('Eloquent\Lockbox\Key\Exception\InvalidSaltSizeException');
        $this->deriver->deriveKeyFromPassword('foobar', 10, 'foobar');
    }

    public function testInstance()
    {
        $className = get_class($this->deriver);
        Liberator::liberateClass($className)->instance = null;
        $instance = $className::instance();

        $this->assertInstanceOf($className, $instance);
        $this->assertSame($instance, $className::instance());
    }
}
