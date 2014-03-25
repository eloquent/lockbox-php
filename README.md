# Lockbox for PHP

*Simple, strong encryption.*

[![The most recent stable version is 0.2.0][version-image]][Semantic versioning]
[![Current build status image][build-image]][Current build status]
[![Current coverage status image][coverage-image]][Current coverage status]

## Installation and documentation

* Available as [Composer] package [eloquent/lockbox].
* [API documentation] available.

## What is *Lockbox*?

*Lockbox* is the simplest possible way to implement strong, two-way, public-key
encryption for use in applications. *Lockbox* uses a combination of
well-established technologies to ensure the safety of data. For more
information, see the [Lockbox website].

## Usage

### Generating keys via OpenSSL

*Lockbox* uses [RSA] keys in [PEM] format. This is a standard format understood
by [OpenSSL]. Generating of keys is normally handled by the `openssl` command
line tool (although *Lockbox* can also generate keys programmatically).
Generating a 2048-bit private key can be achieved with this command:

    openssl genrsa -out private.pem 2048

Private keys can have password protection. To create a key with a password,
simply add the `-des3` flag, which will prompt for password input before the key
is created:

    openssl genrsa -des3 -out private.pem 2048

This private key must be kept secret, and treated as sensitive data. Private
keys are the only keys capable of decrypting data. Public keys, on the other
hand, are not as sensitive, and can be given to any party that will be
responsible for encrypting data.

*Lockbox* is capable of extracting public keys from private keys, there is no
need to create matching public key files; but if for some reason a public key
file is required, this command will create one:

    openssl rsa -pubout -in private.pem -out public.pem

### Generating keys programmatically

```php
use Eloquent\Lockbox\Key\KeyFactory;

$keyFactory = new KeyFactory;

$privateKey = $keyFactory->generatePrivateKey();
echo $privateKey->string(); // outputs the key in PEM format
echo $privateKey->string('password'); // outputs the key in encrypted PEM format

$publicKey = $privateKey->publicKey();
echo $publicKey->string(); // outputs the key in PEM format
```

### Encrypting data

**Note:** Encryption only requires a public key, but *Lockbox* will also accept
private keys, as in this example.

```php
use Eloquent\Lockbox\EncryptionCipher;
use Eloquent\Lockbox\Key\KeyFactory;

$data = 'Super secret data.';

$keyFactory = new KeyFactory;
$key = $keyFactory->createPrivateKeyFromFile('/path/to/key.pem', 'password');

$cipher = new EncryptionCipher;
$encrypted = $cipher->encrypt($key, $data);
```

### Encrypting multiple data packets with the same key

*Lockbox* includes 'bound' ciphers that are locked to a particular key. These
type of ciphers are convenient for encrypting multiple data packets.

**Note:** Encryption only requires a public key, but *Lockbox* will also accept
private keys, as in this example.

```php
use Eloquent\Lockbox\BoundEncryptionCipher;
use Eloquent\Lockbox\Key\KeyFactory;

$data = array(
    'Super secret data.',
    'Extra secret data.',
    'Mega secret data.',
);

$keyFactory = new KeyFactory;
$key = $keyFactory->createPrivateKeyFromFile('/path/to/key.pem', 'password');

$cipher = new BoundEncryptionCipher($key);

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
$key = $keyFactory->createPrivateKeyFromFile('/path/to/key.pem', 'password');

$cipher = new DecryptionCipher;

try {
    $data = $cipher->decrypt($key, $encrypted);
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
$key = $keyFactory->createPrivateKeyFromFile('/path/to/key.pem', 'password');

$cipher = new BoundDecryptionCipher($key);

foreach ($encrypted as $string) {
    try {
        $data = $cipher->decrypt($string);
    } catch (DecryptionFailedException $e) {
        // decryption failed
    }
}
```

<!-- References -->

[Lockbox website]: http://lqnt.co/lockbox
[OpenSSL]: http://en.wikipedia.org/wiki/OpenSSL
[PEM]: http://en.wikipedia.org/wiki/Privacy-enhanced_Electronic_Mail
[RSA]: http://en.wikipedia.org/wiki/RSA_(algorithm)

[API documentation]: http://lqnt.co/otis/artifacts/documentation/api/
[Composer]: http://getcomposer.org/
[build-image]: http://img.shields.io/travis/eloquent/otis/develop.svg "Current build status for the develop branch"
[Current build status]: https://travis-ci.org/eloquent/otis
[coverage-image]: http://img.shields.io/coveralls/eloquent/otis/develop.svg "Current test coverage for the develop branch"
[Current coverage status]: https://coveralls.io/r/eloquent/otis
[eloquent/otis]: https://packagist.org/packages/eloquent/otis
[Semantic versioning]: http://semver.org/
[version-image]: http://img.shields.io/:semver-0.2.0-yellow.svg "This project uses semantic versioning"
