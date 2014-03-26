# Lockbox for PHP

*Simple, strong encryption.*

[![The most recent stable version is 0.2.0][version-image]][Semantic versioning]
[![Current build status image][build-image]][Current build status]
[![Current coverage status image][coverage-image]][Current coverage status]

## Installation and documentation

* Available as [Composer] package [eloquent/lockbox].
* [API documentation] available.

## What is *Lockbox*?

*Lockbox* is the simplest possible way to implement strong encryption for use in
applications. *Lockbox* uses a combination of well-established technologies to
ensure the safety of data. For more information, see the [Lockbox website].

## Usage

### Generating and writing keys

```php
use Eloquent\Lockbox\Key\KeyGenerator;
use Eloquent\Lockbox\Key\KeyWriter;

$keyGenerator = new KeyGenerator;
$key = $keyGenerator->generateKey();

$keyPath = '/path/to/lockbox.key';
$keyWriter = new KeyWriter;
$keyWriter->writeFile($key, $keyPath);
```

Currently there is no way to generate lockbox keys via the command line, but
this feature is planned.

### Encrypting data

```php
use Eloquent\Lockbox\EncryptionCipher;
use Eloquent\Lockbox\Key\KeyReader;

$keyPath = '/path/to/lockbox.key';
$keyReader = new KeyReader;
$key = $keyReader->readFile($keyPath);

$cipher = new EncryptionCipher;
echo $cipher->encrypt($key, 'Super secret data.');
```

### Encrypting multiple data packets with the same key

*Lockbox* includes 'bound' ciphers that are locked to a particular key. These
type of ciphers are convenient for encrypting multiple data packets.

```php
use Eloquent\Lockbox\BoundEncryptionCipher;
use Eloquent\Lockbox\Key\KeyReader;

$keyPath = '/path/to/lockbox.key';
$keyReader = new KeyReader;
$key = $keyReader->readFile($keyPath);

$cipher = new BoundEncryptionCipher($key);

echo $cipher->encrypt('Super secret data.');
echo $cipher->encrypt('Extra secret data.');
echo $cipher->encrypt('Mega secret data.');
```

### Decrypting data

```php
use Eloquent\Lockbox\DecryptionCipher;
use Eloquent\Lockbox\Exception\DecryptionFailedException;
use Eloquent\Lockbox\Key\KeyReader;

$keyPath = '/path/to/lockbox.key';
$keyReader = new KeyReader;
$key = $keyReader->readFile($keyPath);

$cipher = new DecryptionCipher;

$encrypted =
    '37ms0z6MyzvE49o2-cfAJ6sqs3FhqV9uyCOmMOV6qGbM_kVym0R5akGTdCCqUPh7' .
    'la2HrFDcN8Sce7G_5JEgZndnYezCi8ORi-jB-zS9KIc';

try {
    echo $cipher->decrypt($key, $encrypted);
} catch (DecryptionFailedException $e) {
    echo 'Decryption failed.';
}
```

### Decrypting multiple data packets with the same key

*Lockbox* includes 'bound' ciphers that are locked to a particular key. These
type of ciphers are convenient for decrypting multiple data packets.

```php
use Eloquent\Lockbox\BoundDecryptionCipher;
use Eloquent\Lockbox\Exception\DecryptionFailedException;
use Eloquent\Lockbox\Key\KeyReader;

$keyPath = '/path/to/lockbox.key';
$keyReader = new KeyReader;
$key = $keyReader->readFile($keyPath);

$cipher = new BoundDecryptionCipher($key);

$encrypted = array(
    '37ms0z6MyzvE49o2-cfAJ6sqs3FhqV9uyCOmMOV6qGbM_kVym0R5akGTdCCqUPh7' .
    'la2HrFDcN8Sce7G_5JEgZndnYezCi8ORi-jB-zS9KIc',
    'a-6y2yEe-yVPM5om7BIQK3nJHgvNJbazvR0gQj3xPgBoR_mDEdFSU9Xt7Ea1EpZB' .
    'eopzBRnP5OdiTZQ76RVV7xZ4-Ym1qRzSJ-JPtdMI7Zo',
    'sxLpTbj1ilbw48M721J-Mb492lShhbDLlRQcp54UTzGRUdHd_8OlKFkIea51b1sq' .
    'k16JtnZqaXxHQCThmdE1pBTWvhQNOCK2XPizrdSTLf0',
);

foreach ($encrypted as $string) {
    try {
        echo $cipher->decrypt($string);
    } catch (DecryptionFailedException $e) {
        echo 'Decryption failed.';
    }
}
```

<!-- References -->

[Lockbox website]: http://lqnt.co/lockbox

[API documentation]: http://lqnt.co/lockbox-php/artifacts/documentation/api/
[Composer]: http://getcomposer.org/
[build-image]: http://img.shields.io/travis/eloquent/lockbox-php/develop.svg "Current build status for the develop branch"
[Current build status]: https://travis-ci.org/eloquent/lockbox-php
[coverage-image]: http://img.shields.io/coveralls/eloquent/lockbox-php/develop.svg "Current test coverage for the develop branch"
[Current coverage status]: https://coveralls.io/r/eloquent/lockbox-php
[eloquent/lockbox]: https://packagist.org/packages/eloquent/lockbox
[Semantic versioning]: http://semver.org/
[version-image]: http://img.shields.io/:semver-0.2.0-yellow.svg "This project uses semantic versioning"
