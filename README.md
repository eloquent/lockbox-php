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

$data = 'Super secret data.';

$keyPath = '/path/to/lockbox.key';
$keyReader = new KeyReader;
$key = $keyReader->readFile($keyPath);

$cipher = new EncryptionCipher;
echo $cipher->encrypt($key, $data);
```

### Encrypting multiple data packets with the same key

*Lockbox* includes 'bound' ciphers that are locked to a particular key. These
type of ciphers are convenient for encrypting multiple data packets.

```php
use Eloquent\Lockbox\BoundEncryptionCipher;
use Eloquent\Lockbox\Key\KeyReader;

$data = array(
    'Super secret data.',
    'Extra secret data.',
    'Mega secret data.',
);

$keyPath = '/path/to/lockbox.key';
$keyReader = new KeyReader;
$key = $keyReader->readFile($keyPath);

$cipher = new BoundEncryptionCipher($key);

$encrypted = array();
foreach ($data as $string) {
    echo $cipher->encrypt($string);
}
```

### Decrypting data

```php
use Eloquent\Lockbox\DecryptionCipher;
use Eloquent\Lockbox\Exception\DecryptionFailedException;
use Eloquent\Lockbox\Key\KeyReader;

$encrypted =
    '2TkRH_mVR3eID5heNErkHJhJ5kiGyKNG' .
    'UOd41GS5LCzAVvJUVeDi_Rbs0pVbUus2' .
    'i8CTI0Sr0tt5cdPKvuxF9k2gJETEk6KE' .
    't1T63Cl4pxo';

$keyPath = '/path/to/lockbox.key';
$keyReader = new KeyReader;
$key = $keyReader->readFile($keyPath);

$cipher = new DecryptionCipher;

try {
    $data = $cipher->decrypt($key, $encrypted);
} catch (DecryptionFailedException $e) {
    echo 'Decryption failed.';
}

echo $data;
```

### Decrypting multiple data packets with the same key

*Lockbox* includes 'bound' ciphers that are locked to a particular key. These
type of ciphers are convenient for decrypting multiple data packets.

```php
use Eloquent\Lockbox\BoundDecryptionCipher;
use Eloquent\Lockbox\Exception\DecryptionFailedException;
use Eloquent\Lockbox\Key\KeyReader;

$encrypted = array(
    '2TkRH_mVR3eID5heNErkHJhJ5kiGyKNG' .
    'UOd41GS5LCzAVvJUVeDi_Rbs0pVbUus2' .
    'i8CTI0Sr0tt5cdPKvuxF9k2gJETEk6KE' .
    't1T63Cl4pxo',
    'aNkLcTqavI9aXJ6sCzgIdki9FtgxWu22' .
    'mRmRcw3MMY6wKA1hzunGX1o9KzwerYQp' .
    'iX-RQb62Bwl9xjxUnl_nRdOepB9zatNc' .
    'k2E_m2jvWXI',
    'V0wpEJUP6ZSvgqiz0hw27j-6FqH74b2l' .
    'Ss48ohbR8kQ3LpNa-Gi5PBW1ZR_p8RN9' .
    '3YFtRQYcguxQl7bFAJhb6Y_5jz_8zRUM' .
    'tOZ0rNZlDpI',
);

$keyPath = '/path/to/lockbox.key';
$keyReader = new KeyReader;
$key = $keyReader->readFile($keyPath);

$cipher = new BoundDecryptionCipher($key);

foreach ($encrypted as $string) {
    try {
        $data = $cipher->decrypt($string);
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
