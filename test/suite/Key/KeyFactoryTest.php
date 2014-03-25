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

        $this->fixturePath = __DIR__ . '/../../fixture/pem';
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
        $this->privateKeyStringPkcs8 = <<<'EOD'
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIE6TAbBgkqhkiG9w0BBQMwDgQIv2lN8R4qMeUCAggABIIEyPIkq+bUvclc9c9b
6WCfySC2k+rSe/ZXUhY6+YdhquWKE4or/k3OFDGMA0JjGZFCUn7wgrxdg9RQ1mzV
aUqatTaSsv8H7yGj90MoVNlDvhBUfh3yRv5kHXwsAQNBivEMBzF0uxKGgCzMdgee
+ieTc818psXtWsVWTvAreZOPGWhMuBRy8Ze+da+qtp7o3RWY/bMMBl6b9zRvzgJM
PU7iyqYV9Rxvrfq9XIHeXkSBpsfokr044M8OOQQSbkCah68QZJz1VGxngaCfJWQ8
9fW/XJOVjEgpaKYFP+CWLN9hQVSiz5th29/hQYCJuU5Xm66NdaYi1lv69zYnwiGU
iDHgMHFfuVXYMcSy1RUKjIAnspqinloltm0BGgH9nC1ZN/04KSKWAOBHbqZTBcoz
tI69GrNF/3x+Ss2vK08gMGuJbfxE5ECh/kUVjsWgD6H6aKxe+rluF5iCHSwETURg
67j1eC7mzNAyHKygLnW1Fmnq07sEKGFq/ONUz5Cvlepf6WxwaAMX4NPjxfBHJkZG
zmRiJiQdXnsjDTsBAgeFVZgM6X57RQyHJRnrDkikW/68b9pm8CDEMOo07wzJkgnw
blwKeVfW4+bPwu6bjMzgWSNHaYD5OGLAOCtQ8FI4mS78WcL2edW6OhI3E6ZGM56i
J5cCHzAAyn/uACgOpUS1O/ATUuzOs5ryFbGXA4GSeTiGPCGMO4cxnagTXD6BUFqC
OYLa2+uR+SmLyuKjv9O9Osj7rqylad/mCpVXsh7crFVkF43gnvz3Fu7/nBV0j/uK
BnKNkF3+gxz77wFWnH6o7oa4XxXlJ1S5ZgTXdj11hX9vricTeMWXoppKJS56RB0J
WdQdD66pPl4w2S9j4aCIDwYk5H/QBL1QgTOO9SsxT0a7q0T9czJMWyQmo8Wo8vJx
x6euGTpM7i3vKENtMjZLROa25XeC2n0RFGxLcfp8clSczG3iWMgicfwAnRqOvfIv
5jp3yqFzH8RTshJXRvYDBgHKHPtal71ksCcf+SIxyjs6+uULTRLp7L/jR3/R4zHg
KZDdVomizSWAjj+R2dmvvuq4IQtPzKd4XSlQA/5YVBjAGWSIGn/UcSsRyKWlIdcP
QkeAMOWLEVa3/2js26DQlm5BLHNlrCO7uhNWH6yy8iFKSVzvCZWMjGaUCMWBUpz6
5nTxLor2Oj3CoWNU0gvIJS/zolVwxBYGtvRIliRNijn/Qoh9rBxiufro3Ji4VRSW
R69mrqB/4OlGveiAjH4iWPWsFQiz2tEqSiAuFgE6pCmZcxA5hLSoSpw+jbcEDrU3
eYWbtKQqnfm28y6Ae74lvaWboVgK2/EEE4vTzk62iFnH2LPucXynlKNaSyG0goRC
k82Z4PILJfha/pFjEocqEXfJ8noVzLZX30OxNjAQ0LhI779MyZA2shYoh0qc+86e
ENU84OG21wHp4xwwxStbt/jbzCz67hjc/iqmvnjLdaooOVCDeUl0yYs81uvAIKvp
j6LhbAFLemlaWVtkOqgQTs1dO1uTFCID21/pQUxnRxDRSEiyRq4a/XAD/FezeLQv
OeQp2EYIQysr8XpbOaPYOW99uFIQCALmJ5a1JJfDDWvcR6crJkjI60B3NirZSR/p
CdU3lo063CcRZy7m3A==
-----END ENCRYPTED PRIVATE KEY-----

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
        $this->privateKeyStringNoPasswordPkcs8 = <<<'EOD'
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDLyOyWN3HOyC9u
gLK2aUfdDTe/fR89M18yqbPZifQZ22SpAfTX4f3LltZYJDJ4Y4BO8g+sQsZ4H2dG
VB5pNvlWMKXVX09h4zpDfQ8rrjXV8l7GNgD9RtEb/0j8r4D1QF8m9SyMZVQzFlHy
fyOaZLLwbZ6pcFs/p0RkWc7RXbvhNFMHdIsoPa19gFjAy1epP6tJsfU7KhLb0DTc
VpSCRGTV6vaLeV3I0gby8wa/shqC6nr3IGu3zGjrUgWPvp2ShxujOnVjhIbPKORH
+6RFIt77R6NLh4zLOJofsnnZdfWsMWt6KdlkOgTnvVqZ67RuK4zppPw/WmTzlUio
cuWpGb+9AgMBAAECggEACWpbJAWjyH4PUve3Sh5LJ7d4n+xUCSvadijJGn/5O0ib
ugNRILhcVY++j4v8mPtf7kXY24iqStqIlwND9HCJzKWqw9UHgepRwtSAYvBFpIDy
SA4utYUUHEsLQEGLn8k9nDsvt7zmywV4+89MAdItQlaOQh3i2WoNCuXrXFkMWTdQ
drByi9l5SnhECpQt4sNcBBNAlhcTx6s+OFBjS5JY5F7VLUgJojZqpuOYgcVTM+XP
jkqVqTMvCfi2ht6Ip41oes/D74kxc1VKU+SEbE+WJdtlq5qgMdr+nrDeEO+vZmM4
tTtAMeB2JZngRRbkBBF/tqIq0TbI09MYlBvK/1AfMQKBgQD9RCW56wAGn5Qm+8PN
sSYOSKmAJsS7l8fIZvwLQU9kRPXKzbC7QMghphHiGJh62u/mKcfNecxKS5BIzM9r
5LIFeCIacH0nb6wFfQf1vKrdC4yuJNINA8Cm3FmVgBdMRdFSw1gbf9UKILvlWNu5
8cjtCaw5K1OKPrDXmByFOsG35wKBgQDN/AtqaIaaBVuUnXGv7zPBky/31zbaPwr4
Kbg+hSFDojpdyCofIOPyYPrlTFBTdoTxHaa9tftdbWOul+VtXChGglL3PwXvuubq
3fzJLdYmrPqTKhDS7hbabwPyD9ZZE6N4YUOWOumLASuSbMIas2FKTg71hNes1QaQ
PkxOlU8GuwKBgGWZ2BScjLcbf4CgEW3L+jtStQTfCJ9FBXWEsuoE+kd8TqpcF+EW
3PJ6v8PXIBxxBjpsWmY4zVakt64s060x4qTFC9FVfS+74eOVxAK1/EmO35Hg3Y8x
CTEnRpzt9Oq5O38bNJZbkuhsN1SLcCJJN9S3w6pvkiTsf18N+6sK5jnTAoGBAMML
/B9JVNN5aUujfmhy35ZX8l8DuhwVACUXFDCXTXVGo2/0PvZ05YO4kzsW9STjIGVU
h3QyYxAHqhFEIepZDoYdl8QpOEzVtR0HEPvK3HKI70j01zN0Yc16u8i1eGmmr+8o
YqBZrpWCiSjAtVglLWX33jBcFwHAQdPKOeVbepZLAoGBANmjS4wxZ69EGuI9Po4J
0RjCc5k4y+Hot1cbbDILbBgxj7xc4zMOtk/MPeLjBBgJ8mDunKFW1y0HPY1Dwnzv
zGbYRfNSkZojGMshdvVRWDDhddwzsuSMVponWIysxMsZJfz36BbcGDyHFLuSXFl/
tmVVLMukDaOQreTm92BYZWG0
-----END PRIVATE KEY-----

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

    public function testGeneratePrivateKey()
    {
        $key = $this->factory->generatePrivateKey();

        $this->assertInstanceOf(__NAMESPACE__ . '\PrivateKey', $key);
        $this->assertSame(2048, $key->size());
        $this->assertSame('AQAB', base64_encode($key->publicExponent()));
    }

    public function testGeneratePrivateKeyLargeKey()
    {
        $key = $this->factory->generatePrivateKey(4096);

        $this->assertInstanceOf(__NAMESPACE__ . '\PrivateKey', $key);
        $this->assertSame(4096, $key->size());
        $this->assertSame('AQAB', base64_encode($key->publicExponent()));
    }

    public function testCreatePrivateKeyWithPassword()
    {
        $key = $this->factory->createPrivateKey($this->privateKeyString, 'password');

        $this->assertInstanceOf(__NAMESPACE__ . '\PrivateKey', $key);
        $this->assertSame($this->publicKeyString, $key->publicKey()->string());
    }

    public function testCreatePrivateKeyWithPasswordPkcs8()
    {
        $key = $this->factory->createPrivateKey($this->privateKeyStringPkcs8, 'password');

        $this->assertInstanceOf(__NAMESPACE__ . '\PrivateKey', $key);
        $this->assertSame($this->publicKeyString, $key->publicKey()->string());
    }

    public function testCreatePrivateKeyNoPassword()
    {
        $key = $this->factory->createPrivateKey($this->privateKeyStringNoPassword);

        $this->assertInstanceOf(__NAMESPACE__ . '\PrivateKey', $key);
        $this->assertSame($this->publicKeyStringNoPassword, $key->publicKey()->string());
    }

    public function testCreatePrivateKeyNoPasswordPkcs8()
    {
        $key = $this->factory->createPrivateKey($this->privateKeyStringNoPasswordPkcs8);

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
