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

        $this->key = $this->factory->createPrivateKeyFromFile($this->fixturePath . '/rsa-2048-nopass.private.pem');
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
        $this->assertSame(
            'CWpbJAWjyH4PUve3Sh5LJ7d4n+xUCSvadijJGn/5O0ibugNRILhcVY++j4v8mPtf7kXY24iqStqIlwND9HCJzKWqw9UHgepRwtSAYvBF' .
            'pIDySA4utYUUHEsLQEGLn8k9nDsvt7zmywV4+89MAdItQlaOQh3i2WoNCuXrXFkMWTdQdrByi9l5SnhECpQt4sNcBBNAlhcTx6s+OFBj' .
            'S5JY5F7VLUgJojZqpuOYgcVTM+XPjkqVqTMvCfi2ht6Ip41oes/D74kxc1VKU+SEbE+WJdtlq5qgMdr+nrDeEO+vZmM4tTtAMeB2JZng' .
            'RRbkBBF/tqIq0TbI09MYlBvK/1AfMQ==',
            base64_encode($this->key->privateExponent())
        );
        $this->assertSame(
            '/UQluesABp+UJvvDzbEmDkipgCbEu5fHyGb8C0FPZET1ys2wu0DIIaYR4hiYetrv5inHzXnMSkuQSMzPa+SyBXgiGnB9J2+sBX0H9byq' .
            '3QuMriTSDQPAptxZlYAXTEXRUsNYG3/VCiC75VjbufHI7QmsOStTij6w15gchTrBt+c=',
            base64_encode($this->key->prime1())
        );
        $this->assertSame(
            'zfwLamiGmgVblJ1xr+8zwZMv99c22j8K+Cm4PoUhQ6I6XcgqHyDj8mD65UxQU3aE8R2mvbX7XW1jrpflbVwoRoJS9z8F77rm6t38yS3W' .
            'Jqz6kyoQ0u4W2m8D8g/WWROjeGFDljrpiwErkmzCGrNhSk4O9YTXrNUGkD5MTpVPBrs=',
            base64_encode($this->key->prime2())
        );
        $this->assertSame(
            'ZZnYFJyMtxt/gKARbcv6O1K1BN8In0UFdYSy6gT6R3xOqlwX4Rbc8nq/w9cgHHEGOmxaZjjNVqS3rizTrTHipMUL0VV9L7vh45XEArX8' .
            'SY7fkeDdjzEJMSdGnO306rk7fxs0lluS6Gw3VItwIkk31LfDqm+SJOx/Xw37qwrmOdM=',
            base64_encode($this->key->primeExponent1())
        );
        $this->assertSame(
            'wwv8H0lU03lpS6N+aHLfllfyXwO6HBUAJRcUMJdNdUajb/Q+9nTlg7iTOxb1JOMgZVSHdDJjEAeqEUQh6lkOhh2XxCk4TNW1HQcQ+8rc' .
            'cojvSPTXM3RhzXq7yLV4aaav7yhioFmulYKJKMC1WCUtZffeMFwXAcBB08o55Vt6lks=',
            base64_encode($this->key->primeExponent2())
        );
        $this->assertSame(
            '2aNLjDFnr0Qa4j0+jgnRGMJzmTjL4ei3VxtsMgtsGDGPvFzjMw62T8w94uMEGAnyYO6coVbXLQc9jUPCfO/MZthF81KRmiMYyyF29VFY' .
            'MOF13DOy5IxWmidYjKzEyxkl/PfoFtwYPIcUu5JcWX+2ZVUsy6QNo5Ct5Ob3YFhlYbQ=',
            base64_encode($this->key->coefficient())
        );
    }

    public function keyData()
    {
        //                                   name                           password    size  publicKey
        return array(
            '2048-bit, no password' => array('rsa-2048-nopass.private.pem', null,       2048, 'rsa-2048-nopass.public.pem'),
            '2048-bit'              => array('rsa-2048.private.pem',        'password', 2048, 'rsa-2048.public.pem'),
            '4096-bit, no password' => array('rsa-4096-nopass.private.pem', null,       4096, 'rsa-4096-nopass.public.pem'),
        );
    }

    /**
     * @dataProvider keyData
     */
    public function testKey($name, $password, $size, $publicName)
    {
        $key = $this->factory->createPrivateKeyFromFile(sprintf('%s/%s', $this->fixturePath, $name), $password);
        $publicKey = $this->factory->createPublicKeyFromFile(sprintf('%s/%s', $this->fixturePath, $publicName));

        $this->assertSame($size, $key->size());
        $this->assertSame($publicKey->string(), $key->publicKey()->string());
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
        $key = $this->factory->createPrivateKey($string);

        $this->assertSame($string, $key->string());
        $this->assertSame($this->key->size(), $key->size());
        $this->assertSame(base64_encode($this->key->modulus()), base64_encode($key->modulus()));
        $this->assertSame(base64_encode($this->key->publicExponent()), base64_encode($key->publicExponent()));
        $this->assertSame(base64_encode($this->key->privateExponent()), base64_encode($key->privateExponent()));
        $this->assertSame(base64_encode($this->key->prime1()), base64_encode($key->prime1()));
        $this->assertSame(base64_encode($this->key->prime2()), base64_encode($key->prime2()));
        $this->assertSame(base64_encode($this->key->primeExponent1()), base64_encode($key->primeExponent1()));
        $this->assertSame(base64_encode($this->key->primeExponent2()), base64_encode($key->primeExponent2()));
        $this->assertSame(base64_encode($this->key->coefficient()), base64_encode($key->coefficient()));
    }

    public function testStringEncrypted()
    {
        $string = $this->key->string('password');
        $key = $this->factory->createPrivateKey($string, 'password');

        $this->assertSame($this->key->string(), $key->string());
        $this->assertSame($this->key->size(), $key->size());
        $this->assertSame(base64_encode($this->key->modulus()), base64_encode($key->modulus()));
        $this->assertSame(base64_encode($this->key->publicExponent()), base64_encode($key->publicExponent()));
        $this->assertSame(base64_encode($this->key->privateExponent()), base64_encode($key->privateExponent()));
        $this->assertSame(base64_encode($this->key->prime1()), base64_encode($key->prime1()));
        $this->assertSame(base64_encode($this->key->prime2()), base64_encode($key->prime2()));
        $this->assertSame(base64_encode($this->key->primeExponent1()), base64_encode($key->primeExponent1()));
        $this->assertSame(base64_encode($this->key->primeExponent2()), base64_encode($key->primeExponent2()));
        $this->assertSame(base64_encode($this->key->coefficient()), base64_encode($key->coefficient()));
    }

    public function testToString()
    {
        $string = strval($this->key);
        $key = $this->factory->createPrivateKey($string);

        $this->assertSame($string, $key->string());
        $this->assertSame($this->key->size(), $key->size());
        $this->assertSame(base64_encode($this->key->modulus()), base64_encode($key->modulus()));
        $this->assertSame(base64_encode($this->key->publicExponent()), base64_encode($key->publicExponent()));
        $this->assertSame(base64_encode($this->key->privateExponent()), base64_encode($key->privateExponent()));
        $this->assertSame(base64_encode($this->key->prime1()), base64_encode($key->prime1()));
        $this->assertSame(base64_encode($this->key->prime2()), base64_encode($key->prime2()));
        $this->assertSame(base64_encode($this->key->primeExponent1()), base64_encode($key->primeExponent1()));
        $this->assertSame(base64_encode($this->key->primeExponent2()), base64_encode($key->primeExponent2()));
        $this->assertSame(base64_encode($this->key->coefficient()), base64_encode($key->coefficient()));
    }
}
