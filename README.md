# Lockbox for PHP

*Simple, strong encryption.*

[![Build Status]][Latest build]
[![Test Coverage]][Test coverage report]
[![Uses Semantic Versioning]][SemVer]

## Installation and documentation

* Available as [Composer] package [eloquent/lockbox].
* [API documentation] available.

## What is *Lockbox*?

*Lockbox* is designed to be the simplest possible way to implement strong,
two-way, public-key encryption. *Lockbox* uses a combination of well-established
technologies to ensure the safety of data.

### Design goals

- To utilize extremely strong encryption.
- To use existing, well-vetted, open standards where possible.
- To be completely transparent (data out is, byte-for-byte, exactly equal to
  data in).
- To be able to detect decryption failures.
- To be able to encrypt any string, including empty strings.
- To produce ciphertext that is as portable as possible (able to be transmitted
  across many protocols without need for additional encoding).
- To make integration as simple as possible.
- To eliminate the need for configuration.
- To be simple to implement across many languages and platforms.

## Usage

### Generating keys

Generating of keys is handled by the `openssl` command line tool (not part of
*Lockbox*). Generating a private 2048-bit RSA key in PEM format with no password
can be done with this command:

    openssl genrsa -out private.pem 2048

To create a key with a password, simply add the `-des3` flag, which will prompt
for password input before the key is created:

    openssl genrsa -des3 -out private.pem 2048

This private key must be kept secret, and treated as sensitive data. Private
keys are the only keys capable of decrypting data. Public keys, on the other
hand, are not as sensitive, and can be given to any party that will be
responsible for encrypting data.

*Lockbox* is capable of extracting public keys from private keys, there is no
need to create matching public key files; but if for some reason a public key
file is required, this command will create one (from an RSA key in this
example):

    openssl rsa -pubout -in private.pem -out public.pem

### Encrypting data

```php
use Eloquent\Lockbox\EncryptionCipher;
use Eloquent\Lockbox\Key\KeyFactory;

$data = 'Super secret data.';

$keyFactory = new KeyFactory;
$privateKey = $keyFactory->createPrivateKeyFromFile('/path/to/key.pem', 'password');
$publicKey = $privateKey->publicKey();

$cipher = new EncryptionCipher;
$encrypted = $cipher->encrypt($publicKey, $data);
```

### Encrypting multiple data packets with the same key

*Lockbox* includes 'bound' ciphers that are locked to a particular key. These
type of ciphers are convenient for encrypting multiple data packets.

```php
use Eloquent\Lockbox\BoundEncryptionCipher;
use Eloquent\Lockbox\Key\KeyFactory;

$data = array(
    'Super secret data.',
    'Extra secret data.',
    'Mega secret data.',
);

$keyFactory = new KeyFactory;
$privateKey = $keyFactory->createPrivateKeyFromFile('/path/to/key.pem', 'password');
$publicKey = $privateKey->publicKey();

$cipher = new BoundEncryptionCipher($publicKey);

$encrypted = array();
foreach ($data as $string) {
    $encrypted[] = $cipher->encrypt($string);
}
```

### Decrypting data

```php
use Eloquent\Lockbox\DecryptionCipher;
use Eloquent\Lockbox\Exception\DecryptionFailedException;
use Eloquent\Lockbox\Key\KeyFactory;

$encrypted = '<some encrypted data>';

$keyFactory = new KeyFactory;
$privateKey = $keyFactory->createPrivateKeyFromFile('/path/to/key.pem', 'password');

$cipher = new DecryptionCipher;

try {
    $data = $cipher->decrypt($privateKey, $encrypted);
} catch (DecryptionFailedException $e) {
    // decryption failed
}
```

### Decrypting multiple data packets with the same key

*Lockbox* includes 'bound' ciphers that are locked to a particular key. These
type of ciphers are convenient for decrypting multiple data packets.

```php
use Eloquent\Lockbox\BoundDecryptionCipher;
use Eloquent\Lockbox\Exception\DecryptionFailedException;
use Eloquent\Lockbox\Key\KeyFactory;

$encrypted = array(
    '<some encrypted data>',
    '<more encrypted data>',
    '<other encrypted data>',
);

$keyFactory = new KeyFactory;
$privateKey = $keyFactory->createPrivateKeyFromFile('/path/to/key.pem', 'password');

$cipher = new BoundDecryptionCipher($privateKey);

foreach ($encrypted as $string) {
    try {
        $data = $cipher->decrypt($string);
    } catch (DecryptionFailedException $e) {
        // decryption failed
    }
}
```

## How does *Lockbox* actually work?

*Lockbox* uses [OpenSSL] with [PEM] formatted keys, and is similar in operation
to the PHP functions [openssl_seal()] and [openssl_open()].

Where *Lockbox* differs, is in its use of [AES-256] instead of [RC4] as the
secondary encryption algorithm. In addition, *Lockbox* includes data
verification steps that allow unsuccessful decryption to be detected.

### Encryption process

1. Some data and a [public key] are passed to *Lockbox*.
2. A [SHA-1] hash of the data and the data itself are concatenated together.
3. This hash and data concatenation is padded using [PKCS #7] padding.
4. A random 256-bit key and 128-bit [initialization vector][] (IV) are
   generated (by default, *Lockbox* uses /dev/urandom as the random source).
5. The padded hash and data are encrypted using the generated key and IV and
   [AES-256] encryption.
6. The generated key and IV are concatenated together and encrypted with the
   public key using [OpenSSL] and [OAEP padding].
7. The encrypted key and IV, and the encrypted hash and data are concatenated
   together.
8. This concatenation of encrypted data is then encoded using [Base64 with a URI
   and filename safe alphabet].
9. This encoded data is returned as the final ciphertext.

### Decryption process

1.  Some ciphertext and a [private key] are passed to *Lockbox*.
2.  The ciphertext is decoded using [Base64 with a URI and filename safe
    alphabet].
3.  The first n bits of the ciphertext are extracted, where n is the size of the
    private key; this extracted data is the encrypted key and [initialization
    vector] (IV).
4.  The remaining bits of the ciphertext are extracted as the encrypted data
5.  The encrypted key and IV from step 3 are decrypted with the private key
    using [OpenSSL] and [OAEP padding].
6.  The first 256 bits of the decrypted data are extracted as the key.
7.  The next 128 bits of the decrypted data are extracted as the IV.
8.  The encrypted data from step 4 is decrypted using the recovered key and IV
    from steps 6 and 7 and [AES-256] encryption.
9.  Padding is removed from the decrypted data in accordance with the [PKCS #7]
    padding scheme.
10. The first 160 bits of the unpadded data are extracted as the verification
    hash.
11. The remaining bits of the unpadded data are extracted as the final data.
12. If the verification hash matches the [SHA-1] hash of the final data, the
    final data is returned, otherwise decryption has failed.

## Test vectors

All test vectors use the following key:

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

All test vector values below are expressed as [US-ASCII] encoded strings.
Newlines are added only for readability, and do not make up part of the value.

Note that the [OpenSSL] encrypted portion of the ciphertext will be different
each time because it utilizes a random seed. Therefore only the ciphertext after
the 342<sup>nd</sup> byte is guaranteed to be the same for all ciphertext.

    Data:               1234
    Generated key:      12345678901234567890123456789012
    Generated IV:       1234567890123456
    Example ciphertext: wdPXCy5amuY7U8tGD0M-nnK5LGc4DC1h
                        VwvNWVLCyqOMHgDF3fpsY-8MQkMUuI0T
                        eNoutU-TpuGsm6D-KIXeAaWIYuUAaNZ-
                        V_5WwmRFT5BEyhQwZ3PFybrs39o4sAlO
                        d5IVvLNMMgwRD-FmQc8KU10d3KDd71wW
                        r50y7R33xTnyJplx9uqcOrB6ooQLjFcF
                        bFU87YPnhkxZK5JryTxAlaDJjfFs-3XM
                        zgoJ35rpBgDVywPXbye1C8u5gw81awid
                        Xgei_a27MZog1lUvETzMXqqZ4VlhckDV
                        m71f4TLMKHTz-CmYinvzj7G_pYmvtHeh
                        uxDzjdrT4lbetTuESm-YHKtq9JEj6E2S
                        ER4TURlVKf14sPeDgRUo88-zvM7BWpMv

    Data:               1234567890123456
    Generated key:      12345678901234567890123456789012
    Generated IV:       1234567890123456
    Example ciphertext: umvbDKEQtKldCN15bgyGyLm5K5LEDNGJ
                        kXbyYask_sgSi9lkGa5ByDZKVs1SMgp0
                        mif4GDfyg5xVadsPzoH9-jdSoTB7pNxz
                        ns8CNP8KIWEcU6TATwjbW9bP5FBQKxRO
                        OTHdLLJ7ADqvuT0QxH1Yy1xzlVGXUXxk
                        coMBey_CxiboqjLm_cEl1dA0HyidgxTn
                        rArsM7porZPj__gbWIEv58L0S2xv11YL
                        0IQMGkQiupJhHKiyAIH4KchZ8whV_aAZ
                        193U7toEJ7Ojd7uu6hzMiVDCIRPDa5Ek
                        zyBFoNsr2hcTFcU4oxBkRbUottvH9Dji
                        SxIPU4O8vomXpUqWzneJ4CBlVmSYgUJa
                        4zsJUnll4lufFRTYTYjuCgQhunOAIVS2
                        DxuQH8bSZZrHKNIghc0D3Q

<!-- References -->

[AES-256]: http://en.wikipedia.org/wiki/Advanced_Encryption_Standard
[Base64 with a URI and filename safe alphabet]: http://tools.ietf.org/html/rfc4648#section-5
[initialization vector]: http://en.wikipedia.org/wiki/Initialization_vector
[OEAP padding]: http://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
[OpenSSL]: http://www.openssl.org/
[openssl_open()]: http://php.net/openssl_open
[openssl_seal()]: http://php.net/openssl_seal
[PEM]: http://en.wikipedia.org/wiki/Privacy_Enhanced_Mail
[PKCS #7]: http://tools.ietf.org/html/rfc2315
[private key]: http://en.wikipedia.org/wiki/Public-key_cryptography
[public key]: http://en.wikipedia.org/wiki/Public-key_cryptography
[RC4]: http://en.wikipedia.org/wiki/RC4
[SHA-1]: http://tools.ietf.org/html/rfc3174
[US-ASCII]: http://en.wikipedia.org/wiki/ASCII

[API documentation]: http://lqnt.co/lockbox-php/artifacts/documentation/api/
[Build Status]: https://api.travis-ci.org/eloquent/lockbox-php.png?branch=master
[Composer]: http://getcomposer.org/
[eloquent/lockbox]: https://packagist.org/packages/eloquent/lockbox
[Latest build]: https://travis-ci.org/eloquent/lockbox-php
[SemVer]: http://semver.org/
[Test coverage report]: https://coveralls.io/r/eloquent/lockbox-php
[Test Coverage]: https://coveralls.io/repos/eloquent/lockbox-php/badge.png?branch=master
[Uses Semantic Versioning]: http://b.repl.ca/v1/semver-yes-brightgreen.png
