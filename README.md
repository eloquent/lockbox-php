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
use Eloquent\Lockbox\Key\Generator\KeyGenerator;
use Eloquent\Lockbox\Key\Persistence\KeyWriter;

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
use Eloquent\Lockbox\Encrypter;
use Eloquent\Lockbox\Key\Persistence\KeyReader;

$keyPath = '/path/to/lockbox.key';
$keyReader = new KeyReader;
$key = $keyReader->readFile($keyPath);

$encrypter = new Encrypter;
echo $encrypter->encrypt($key, 'Super secret data.');
```

### Encrypting multiple data packets with the same key

*Lockbox* includes 'bound' encrypters that are locked to a particular key, which
are convenient for encrypting multiple data packets.

```php
use Eloquent\Lockbox\Bound\BoundEncrypter;
use Eloquent\Lockbox\Key\Persistence\KeyReader;

$keyPath = '/path/to/lockbox.key';
$keyReader = new KeyReader;
$key = $keyReader->readFile($keyPath);

$encrypter = new BoundEncrypter($key);

echo $encrypter->encrypt('Super secret data.');
echo $encrypter->encrypt('Extra secret data.');
echo $encrypter->encrypt('Mega secret data.');
```

### Decrypting data

```php
use Eloquent\Lockbox\Decrypter;
use Eloquent\Lockbox\Key\Persistence\KeyReader;

$keyPath = '/path/to/lockbox.key';
$keyReader = new KeyReader;
$key = $keyReader->readFile($keyPath);

$decrypter = new Decrypter;

$encrypted =
    'AQF_VjJS9sAL75uuUP_HTu9Do_3itIDaHLLXmh_JLOBRqQeZ_hnDwht4WtEkz3io' .
    'iW0WIHb3lANyKqpShyiPcVdj_DbfYiIPEWab8e3vqwEUvoqFFNo';

$result = $decrypter->decrypt($key, $encrypted);
if ($result->isSuccessful()) {
    echo $result->data();
} else {
    echo 'Decryption failed.';
}
```

### Decrypting multiple data packets with the same key

*Lockbox* includes 'bound' decrypters that are locked to a particular key, which
are convenient for decrypting multiple data packets.

```php
use Eloquent\Lockbox\Bound\BoundDecrypter;
use Eloquent\Lockbox\Key\Persistence\KeyReader;

$keyPath = '/path/to/lockbox.key';
$keyReader = new KeyReader;
$key = $keyReader->readFile($keyPath);

$decrypter = new BoundDecrypter($key);

$encrypted = array(
    'AQF_VjJS9sAL75uuUP_HTu9Do_3itIDaHLLXmh_JLOBRqQeZ_hnDwht4WtEkz3io' .
    'iW0WIHb3lANyKqpShyiPcVdj_DbfYiIPEWab8e3vqwEUvoqFFNo',
    'AQH44yTs7va1cDoBpX0xVLqIRow5fs8Jj5-DYDJ1R3YY9udBCexmvDs9BH1qJDjC' .
    'RSqcGriKi_UkL5per1WHwdxWuPq8QsYiBqeC9e9zypl0Xi1QT3s',
    'AQGg0MsYtH0Rboyqssivssupb_GKlBotCpdFtc6WpnMaji8_ZvmGUTRu2DKkxFhA' .
    'dk_s0FWZ7NYFjSDt1puIrr7MlB7owNuR5KhUIj04Can0zDCYjJY',
);

foreach ($encrypted as $string) {
    $result = $decrypter->decrypt($string);
    if ($result->isSuccessful()) {
        echo $result->data();
    } else {
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
