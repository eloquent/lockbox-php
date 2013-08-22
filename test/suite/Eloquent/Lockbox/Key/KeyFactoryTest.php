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
        $this->publicKeyString = <<<'EOD'
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

    public function testCreatePrivateKey()
    {
        $key = $this->factory->createPrivateKey($this->privateKeyString);

        $this->assertInstanceOf(__NAMESPACE__ . '\PrivateKey', $key);
        $this->assertSame($this->publicKeyString, $key->publicKey()->string());
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

    public function testCreatePrivateKeyFromFile()
    {
        $key = $this->factory->createPrivateKeyFromFile($this->fixturePath . '/rsa-2048-nopass.private.pem');

        $this->assertInstanceOf(__NAMESPACE__ . '\PrivateKey', $key);
        $this->assertSame($this->publicKeyString, $key->publicKey()->string());
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
        $key = $this->factory->createPublicKeyFromFile($this->fixturePath . '/rsa-2048-nopass.public.pem');

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
