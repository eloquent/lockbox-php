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

    public function testConstructorFailureNotRsa()
    {
        $keyString = <<<'EOD'
-----BEGIN PUBLIC KEY-----
MIIDRjCCAjkGByqGSM44BAEwggIsAoIBAQDCH7BljSJrIaN4h4+WoeUPDho9dJeu
3XhlEVGR4I3jtGP9lNj8zvkFmK4m7KbHO6UwqyszxHzgJQof61gkjBR60g8jMf8o
F5r2/gs5bOzhsbYfIlBlZJqYxjAv6HFrsy6cVsU82ppyXdSTyy5vqBqIC+SNzzdR
5Ia3sfz86AyilL4hvMcw9ETqk5H93mIkgM0KeqWnxYPj/vTPhFMmIwTpd3OMzuqJ
6wHbkM3j4m1fMl8vcU3IiaAVOZSEqx9br2omX/WYFCnq5VXeSdH8ExuDm3g60k0y
n6iegJ4SQTUfopcJ+QHf3jThGfia8uoRqI7AbrgGO3TU5/mUGZVX0Qn5AiEAlZ0n
H7ZxYfRk/8abXesQ1vdF1kUn+jWdGJmqYiz/o9cCggEAKQUw5713oA5YDXirsasZ
hQeNKQ/yn79rfZ4Bu+Kt0A6VIiC9GyazIf6fhMAh4BFFW+RYth7VcLaYoB7+TSdR
vgIETjopPLhz7D4d4UnTeKfxgQOqIU55XWMjNMhf8XDDArx6vxd5b2He/EHIcfmL
oxzS2V4QcQsELFuFvAQjy0ZymAkM6fDhLtEoTonnmEK71bxxbuXXXch9DoYA2n/L
GALZs+v4kMLEsMgVQVTuIbQAUnRY4naaVxkXRRm1u65MTPfyur4Y98kFhdkaXApb
y9204MMjhdIQNzyL87iJ2yTwNCLmP+L1rMdaCmFtlhbzYBd/gzTk0dZdXTceecET
tQOCAQUAAoIBACe2sEtOeap+cCSh3XSY2dtFY8H3L3mrc3uw7QXoyychbwAVUoyR
26XOpq+9ZwTmgujod1njZFwiClw93erIM/omPHrgcjp8u0Cy3zz/YuWbU1S/IglF
mpE7gA/ARGzC0g0/BV1GDfPGWuqRNRndpa+9pxFPb5/RUFWcQBAb00D+VrzEgxHs
7UpZVwY1W/bQYuMHwPqRwefyhsj1nyFyVN2Lrww8WRywyK9Bcs7qVQuL9p7CtDsp
TXj7+ObqS6h7Ch+af9l6vYWwHGl/WdiK6HzEVZgAR1LNc5x7jwEN0/k9hIKPBCQw
j/4BUn0ZHOM64mED3f5Kpd22ZuRLDwj6yJE=
-----END PUBLIC KEY-----

EOD;
        $handle = openssl_pkey_get_public($keyString);

        $this->setExpectedException(__NAMESPACE__ . '\Exception\InvalidPublicKeyException');
        new PublicKey($handle);
    }

    public function testConstructorFailureNotPublic()
    {
        $keyString = <<<'EOD'
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAy8jsljdxzsgvboCytmlH3Q03v30fPTNfMqmz2Yn0GdtkqQH0
1+H9y5bWWCQyeGOATvIPrELGeB9nRlQeaTb5VjCl1V9PYeM6Q30PK6411fJexjYA
/UbRG/9I/K+A9UBfJvUsjGVUMxZR8n8jmmSy8G2eqXBbP6dEZFnO0V274TRTB3SL
KD2tfYBYwMtXqT+rSbH1OyoS29A03FaUgkRk1er2i3ldyNIG8vMGv7Iagup69yBr
t8xo61IFj76dkocbozp1Y4SGzyjkR/ukRSLe+0ejS4eMyziaH7J52XX1rDFreinZ
ZDoE571ameu0biuM6aT8P1pk85VIqHLlqRm/vQIDAQABAoIBAAlqWyQFo8h+D1L3
t0oeSye3eJ/sVAkr2nYoyRp/+TtIm7oDUSC4XFWPvo+L/Jj7X+5F2NuIqkraiJcD
Q/RwicylqsPVB4HqUcLUgGLwRaSA8kgOLrWFFBxLC0BBi5/JPZw7L7e85ssFePvP
TAHSLUJWjkId4tlqDQrl61xZDFk3UHawcovZeUp4RAqULeLDXAQTQJYXE8erPjhQ
Y0uSWORe1S1ICaI2aqbjmIHFUzPlz45KlakzLwn4tobeiKeNaHrPw++JMXNVSlPk
hGxPliXbZauaoDHa/p6w3hDvr2ZjOLU7QDHgdiWZ4EUW5AQRf7aiKtE2yNPTGJQb
yv9QHzECgYEA/UQluesABp+UJvvDzbEmDkipgCbEu5fHyGb8C0FPZET1ys2wu0DI
IaYR4hiYetrv5inHzXnMSkuQSMzPa+SyBXgiGnB9J2+sBX0H9byq3QuMriTSDQPA
ptxZlYAXTEXRUsNYG3/VCiC75VjbufHI7QmsOStTij6w15gchTrBt+cCgYEAzfwL
amiGmgVblJ1xr+8zwZMv99c22j8K+Cm4PoUhQ6I6XcgqHyDj8mD65UxQU3aE8R2m
vbX7XW1jrpflbVwoRoJS9z8F77rm6t38yS3WJqz6kyoQ0u4W2m8D8g/WWROjeGFD
ljrpiwErkmzCGrNhSk4O9YTXrNUGkD5MTpVPBrsCgYBlmdgUnIy3G3+AoBFty/o7
UrUE3wifRQV1hLLqBPpHfE6qXBfhFtzyer/D1yAccQY6bFpmOM1WpLeuLNOtMeKk
xQvRVX0vu+HjlcQCtfxJjt+R4N2PMQkxJ0ac7fTquTt/GzSWW5LobDdUi3AiSTfU
t8Oqb5Ik7H9fDfurCuY50wKBgQDDC/wfSVTTeWlLo35oct+WV/JfA7ocFQAlFxQw
l011RqNv9D72dOWDuJM7FvUk4yBlVId0MmMQB6oRRCHqWQ6GHZfEKThM1bUdBxD7
ytxyiO9I9NczdGHNervItXhppq/vKGKgWa6VgokowLVYJS1l994wXBcBwEHTyjnl
W3qWSwKBgQDZo0uMMWevRBriPT6OCdEYwnOZOMvh6LdXG2wyC2wYMY+8XOMzDrZP
zD3i4wQYCfJg7pyhVtctBz2NQ8J878xm2EXzUpGaIxjLIXb1UVgw4XXcM7LkjFaa
J1iMrMTLGSX89+gW3Bg8hxS7klxZf7ZlVSzLpA2jkK3k5vdgWGVhtA==
-----END RSA PRIVATE KEY-----

EOD;
        $handle = openssl_pkey_get_private($keyString);

        $this->setExpectedException(__NAMESPACE__ . '\Exception\InvalidPublicKeyException');
        new PublicKey($handle);
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
