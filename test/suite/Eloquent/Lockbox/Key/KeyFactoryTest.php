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

use Icecave\Isolator\Isolator;
use Phake;
use PHPUnit_Framework_TestCase;

class KeyFactoryTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->isolator = Phake::partialMock(Isolator::className());
        $this->factory = new KeyFactory($this->isolator);

        $this->fixturePath = __DIR__ . '/../../../../fixture/pem';
        $this->privateKeyString = <<<'EOD'
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,C993FE1F47B61753

YEyAqkV+1qDThx1TYeAEs7eQmT8FkEWv/mnZvebKz3hMweP8/59vGYHzqK6fapGj
WV+UM01IqQQOgsbXdsqn1TyNsOu1QvqLJHQoxkirknAsPfqHHhFCxd0qjY9wW5rp
j29P5SBH+lpizLWa9spjrZuzejI5vDztojy7IJmTu5nsUq1HjyLuhZqBX/JcwDFS
/EGPVPKZcn4bQGUVJ/y1TZIBXkaR8wflVD7ViRh+GrdTjI7biX7LgoY7v0scV25L
NxV/thpxnZEeT5vOeROrPig+aH5VzwimzZ5MSLoCkE0EMJVhrA8xiylIiqw/5xFt
UDWc7DUUGL3OwAEg3EN46vSfgN8tZrFEyoU5//JutZq89few2GbAtyC9sTIxYBxP
1SAc46SM3cHf7MOyuNA4fOceLW3RY6k6GcH9SIBGk49+UWf4TBJg53+Lwj7M57os
o3mg0RtZ1j5snjd8rXKwvTfRMeY70minkPK6RCUwu/aGI9ORGTCOF5FBUXeEEtEC
vgx1mNUjfUK682Q+yjZ3oSMn9pupiGu49XkClxn613be9b/gpKm4Qr62sac/2Y/n
A+zQA4+wevz/zCCoGiktO6AtvIXnuZxGlq4IjzBtYH2D0Z6HatsWWw+LnAeYzSgh
WM/0WjMuiSyYAIQJyqojdIQG+5jwz1WL9mACi8/2r+E1SXcy69ILJn2oWyYLVXD8
vLLK8gV+uKSvmSV2JHYOsuZUGBwyZ75qdY88IaENZTPpZGozh61/mI59seQQqsmZ
T2UD1DiMZZy+/8TW/rpBqiNN8p7Ft/U/OAT2B5j04LIEszMWIJ4ffYF69Xtd/oPU
0p460C1RGxwIhg5bHwfx7w2tEEuM0huBjn9iyaEpJo/YkJpRwGiTi2Xc3Mw5Y2BG
8hdxOvLOpjjGUKjms6QVRqLX2g9hGT5OCKzec4y2Oz9k2aaQ3VCg3fsvlOfP0Yv9
Sh+qJlG66BnrhQ4MMaEbYXpmgp0O4q00+xbInNI83e+Oo3Ia0Oyn6Kbi/4IMaegK
ocH5zr9ONBcUQsibQqu/6b0dSe8Yf2isUtagkFic7ZDsuMmrkmln2PrCBFB2daa8
yWrtZnib9Q2e3QPgFR75kggAmQoN41Y8O2eqw0lHOwBhckE+tSsKkF6dDDyillbB
8XaTllLk2kdC5VGlJtAHGcXDdTgBjyZzbJWt6niJT6KRTWIR6JQk/9t/twmmB9Sr
jXOtCh3/kEDfV+hOFCNNm+mhQdVt8OlevtYnNu3A1sAXpf4Vr3oeaNnvwkqmzlDj
2pbBd7LiJcnP0VvzxSCrErxMBl6s14u2cd5c3r/fiGnaR3u8nxA+GpUPDjD6lNh5
or6BubNGS4NQMrMQ2OL31d5P3qcPZtQoJNdz1MAj5y4qOQBKA384VdIDDF8gJl4k
j5zYqI0tn06/UKWyN3aBknXBKY//LwFBbksSdAeLeHClnbfxpz0hTlj31IT8Td9U
MHgOFCXFKwkUDZH8pou/7Q4eYWwICCcaPp3QA0wv3FNwyBmgamw7quqbk7xiJuz7
1E/yfdAXEjlPRibVjvwpopYitZcGqIS0Mt9bXtwugzdeQh9TF2karA==
-----END RSA PRIVATE KEY-----

EOD;
        $this->publicKeyString = <<<'EOD'
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwpFuTp1Y+b1JZ9k37aJO
7DT7KT6CE426qbH0SmqUmIFCJOxLTnK/tUV/00VMm16XPeOLQwIGAL5+RpcjIQA8
VEgZKvJQ4bPlRTIm/SKP0goCzUbP7hUbtuaUQvXFrrlcl4YRoF2bwbp3BR3ikUE8
ir6ZtiCTJYSawFZQiSq++M/u4ZZ9rYS9OF7NEKDW7bb9SYsHJv4fPlm7hwIWADdj
OdJSsQRVNOoBBOWG8leIPBdlmKq7PaTJlTlgYpW8IIc37LYj5APl26OLWEYI/VQH
HPIE5o9vqKJL0mC0TCrlJv9Z+Bx1408YwFJf32ubc5c0TtvWC9s+8eu+J5bDbzGd
IQIDAQAB
-----END PUBLIC KEY-----

EOD;
        $this->privateKeyStringNoPassword = <<<'EOD'
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
        $this->publicKeyStringNoPassword = <<<'EOD'
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8jsljdxzsgvboCytmlH
3Q03v30fPTNfMqmz2Yn0GdtkqQH01+H9y5bWWCQyeGOATvIPrELGeB9nRlQeaTb5
VjCl1V9PYeM6Q30PK6411fJexjYA/UbRG/9I/K+A9UBfJvUsjGVUMxZR8n8jmmSy
8G2eqXBbP6dEZFnO0V274TRTB3SLKD2tfYBYwMtXqT+rSbH1OyoS29A03FaUgkRk
1er2i3ldyNIG8vMGv7Iagup69yBrt8xo61IFj76dkocbozp1Y4SGzyjkR/ukRSLe
+0ejS4eMyziaH7J52XX1rDFreinZZDoE571ameu0biuM6aT8P1pk85VIqHLlqRm/
vQIDAQAB
-----END PUBLIC KEY-----

EOD;
    }

    public function testCreatePrivateKeyWithPassword()
    {
        $key = $this->factory->createPrivateKey($this->privateKeyString, 'password');

        $this->assertInstanceOf(__NAMESPACE__ . '\PrivateKey', $key);
        $this->assertSame($this->publicKeyString, $key->publicKey()->string());
    }

    public function testCreatePrivateKeyNoPassword()
    {
        $key = $this->factory->createPrivateKey($this->privateKeyStringNoPassword);

        $this->assertInstanceOf(__NAMESPACE__ . '\PrivateKey', $key);
        $this->assertSame($this->publicKeyStringNoPassword, $key->publicKey()->string());
    }

    public function testCreatePrivateKeyFailure()
    {
        $this->setExpectedException(__NAMESPACE__ . '\Exception\InvalidPrivateKeyException');
        $this->factory->createPrivateKey('');
    }

    public function testCreatePublicKey()
    {
        $key = $this->factory->createPublicKey($this->publicKeyString);

        $this->assertInstanceOf(__NAMESPACE__ . '\PublicKey', $key);
        $this->assertSame($this->publicKeyString, $key->string());
    }

    public function testCreatePublicKeyFailure()
    {
        $this->setExpectedException(__NAMESPACE__ . '\Exception\InvalidPublicKeyException');
        $this->factory->createPublicKey('');
    }

    public function testCreatePrivateKeyFromFileWithPassword()
    {
        $key = $this->factory->createPrivateKeyFromFile($this->fixturePath . '/rsa-2048.private.pem', 'password');

        $this->assertInstanceOf(__NAMESPACE__ . '\PrivateKey', $key);
        $this->assertSame($this->publicKeyString, $key->publicKey()->string());
    }

    public function testCreatePrivateKeyFromFileNoPassword()
    {
        $key = $this->factory->createPrivateKeyFromFile($this->fixturePath . '/rsa-2048-nopass.private.pem');

        $this->assertInstanceOf(__NAMESPACE__ . '\PrivateKey', $key);
        $this->assertSame($this->publicKeyStringNoPassword, $key->publicKey()->string());
    }

    public function testCreatePrivateKeyFromFileFailure()
    {
        Phake::when($this->isolator)->file_get_contents(Phake::anyParameters())
            ->thenThrow(Phake::mock('ErrorException'));

        $this->setExpectedException(__NAMESPACE__ . '\Exception\ReadException');
        $this->factory->createPrivateKeyFromFile('foo');
    }

    public function testCreatePublicKeyFromFile()
    {
        $key = $this->factory->createPublicKeyFromFile($this->fixturePath . '/rsa-2048.public.pem');

        $this->assertInstanceOf(__NAMESPACE__ . '\PublicKey', $key);
        $this->assertSame($this->publicKeyString, $key->string());
    }

    public function testCreatePublicKeyFromFileFailure()
    {
        Phake::when($this->isolator)->file_get_contents(Phake::anyParameters())
            ->thenThrow(Phake::mock('ErrorException'));

        $this->setExpectedException(__NAMESPACE__ . '\Exception\ReadException');
        $this->factory->createPublicKeyFromFile('foo');
    }
}
