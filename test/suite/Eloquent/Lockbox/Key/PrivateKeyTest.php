<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Key;

use Eloquent\Liberator\Liberator;
use PHPUnit_Framework_TestCase;

/**
 * @covers Eloquent\Lockbox\Key\PrivateKey
 * @covers Eloquent\Lockbox\Key\AbstractKey
 */
class PrivateKeyTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->factory = new KeyFactory;
        $this->fixturePath = __DIR__ . '/../../../../fixture/pem';
    }

    public function testConstructor()
    {
        $key = $this->factory->createPrivateKeyFromFile($this->fixturePath . '/rsa-2048-nopass.private.pem');

        $this->assertInternalType('resource', $key->handle());
    }

    public function keyData()
    {
        //                                        name                           password    bits  envelopeSize publicKey
        return array(
            'DSA, 2048-bit, no password' => array('dsa-2048-nopass.private.pem', null,       2048, 256,         'dsa-2048-nopass.public.pem'),
            'DSA, 2048-bit'              => array('dsa-2048.private.pem',        'password', 2048, 256,         'dsa-2048.public.pem'),
            'DSA, 4096-bit, no password' => array('dsa-4096-nopass.private.pem', null,       4096, 512,         'dsa-4096-nopass.public.pem'),
            'RSA, 2048-bit, no password' => array('rsa-2048-nopass.private.pem', null,       2048, 256,         'rsa-2048-nopass.public.pem'),
            'RSA, 2048-bit'              => array('rsa-2048.private.pem',        'password', 2048, 256,         'rsa-2048.public.pem'),
            'RSA, 4096-bit, no password' => array('rsa-4096-nopass.private.pem', null,       4096, 512,         'rsa-4096-nopass.public.pem'),
        );
    }

    /**
     * @dataProvider keyData
     */
    public function testKey($name, $password, $bits, $envelopeSize, $publicName)
    {
        $key = $this->factory->createPrivateKeyFromFile(sprintf('%s/%s', $this->fixturePath, $name), $password);
        $publicKey = $this->factory->createPublicKeyFromFile(sprintf('%s/%s', $this->fixturePath, $publicName));

        $this->assertSame($bits, $key->bits());
        $this->assertSame($envelopeSize, $key->envelopeSize());
        $this->assertSame($publicKey->string(), $key->publicKey()->string());
    }

    public function testDetailFailure()
    {
        $key = Liberator::liberate(
            $this->factory->createPrivateKeyFromFile($this->fixturePath . '/rsa-2048-nopass.private.pem')
        );

        $this->setExpectedException(__NAMESPACE__ . '\Exception\MissingDetailException');
        $key->detail('foo');
    }
}
