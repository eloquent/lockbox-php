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
 * @covers Eloquent\Lockbox\Key\PublicKey
 * @covers Eloquent\Lockbox\Key\AbstractKey
 */
class PublicKeyTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->factory = new KeyFactory;
        $this->fixturePath = __DIR__ . '/../../../../fixture/pem';

        $this->key = $this->factory->createPublicKeyFromFile($this->fixturePath . '/rsa-2048-nopass.public.pem');
    }

    public function testConstructor()
    {
        $this->assertInternalType('resource', $this->key->handle());
        $this->assertSame(
            'y8jsljdxzsgvboCytmlH3Q03v30fPTNfMqmz2Yn0GdtkqQH01+H9y5bWWCQyeGOATvIPrELGeB9nRlQeaTb5VjCl1V9PYeM6Q30PK641' .
            '1fJexjYA/UbRG/9I/K+A9UBfJvUsjGVUMxZR8n8jmmSy8G2eqXBbP6dEZFnO0V274TRTB3SLKD2tfYBYwMtXqT+rSbH1OyoS29A03FaU' .
            'gkRk1er2i3ldyNIG8vMGv7Iagup69yBrt8xo61IFj76dkocbozp1Y4SGzyjkR/ukRSLe+0ejS4eMyziaH7J52XX1rDFreinZZDoE571a' .
            'meu0biuM6aT8P1pk85VIqHLlqRm/vQ==',
            base64_encode($this->key->modulus())
        );
        $this->assertSame('AQAB', base64_encode($this->key->publicExponent()));
    }

    public function keyData()
    {
        //                                   name                          password    size
        return array(
            '2048-bit, no password' => array('rsa-2048-nopass.public.pem', null,       2048),
            '2048-bit'              => array('rsa-2048.public.pem',        'password', 2048),
            '4096-bit, no password' => array('rsa-4096-nopass.public.pem', null,       4096),
        );
    }

    /**
     * @dataProvider keyData
     */
    public function testKey($name, $password, $size)
    {
        $path = sprintf('%s/%s', $this->fixturePath, $name);
        $key = $this->factory->createPublicKeyFromFile($path, $password);

        $this->assertSame($size, $key->size());
        $this->assertSame($key, $key->publicKey());
        $this->assertSame(file_get_contents($path), $key->string());
    }

    public function testDetailFailure()
    {
        $key = Liberator::liberate($this->key);

        $this->setExpectedException(__NAMESPACE__ . '\Exception\MissingDetailException');
        $key->detail('foo');
    }

    public function testRsaDetailFailure()
    {
        $key = Liberator::liberate($this->key);

        $this->setExpectedException(__NAMESPACE__ . '\Exception\MissingDetailException');
        $key->rsaDetail('foo');
    }

    public function testString()
    {
        $string = $this->key->string();
        $key = $this->factory->createPublicKey($string);

        $this->assertSame($string, $key->string());
        $this->assertSame($this->key->size(), $key->size());
        $this->assertSame(base64_encode($this->key->modulus()), base64_encode($key->modulus()));
        $this->assertSame(base64_encode($this->key->publicExponent()), base64_encode($key->publicExponent()));
    }

    public function testToString()
    {
        $string = strval($this->key);
        $key = $this->factory->createPublicKey($string);

        $this->assertSame($string, $key->string());
        $this->assertSame($this->key->size(), $key->size());
        $this->assertSame(base64_encode($this->key->modulus()), base64_encode($key->modulus()));
        $this->assertSame(base64_encode($this->key->publicExponent()), base64_encode($key->publicExponent()));
    }
}
