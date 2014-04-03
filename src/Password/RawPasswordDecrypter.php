<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Password;

use Eloquent\Confetti\TransformStream;
use Eloquent\Confetti\TransformStreamInterface;
use Eloquent\Lockbox\Exception\InvalidPaddingException;
use Eloquent\Lockbox\Exception\PasswordDecryptionFailedException;
use Eloquent\Lockbox\Exception\UnsupportedTypeException;
use Eloquent\Lockbox\Exception\UnsupportedVersionException;
use Eloquent\Lockbox\Key\KeyDeriver;
use Eloquent\Lockbox\Key\KeyDeriverInterface;
use Eloquent\Lockbox\Transform\Factory\PasswordDecryptTransformFactory;
use Eloquent\Lockbox\Transform\Factory\PasswordDecryptTransformFactoryInterface;

/**
 * Decrypts raw data using passwords.
 */
class RawPasswordDecrypter implements PasswordDecrypterInterface
{
    /**
     * Get the static instance of this decrypter.
     *
     * @return PasswordDecrypterInterface The static decrypter.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new raw password decrypter.
     *
     * @param PasswordDecryptTransformFactoryInterface|null $transformFactory The transform factory to use.
     * @param KeyDeriverInterface|null                      $keyDeriver       The key deriver to use.
     */
    public function __construct(
        PasswordDecryptTransformFactoryInterface $transformFactory = null,
        KeyDeriverInterface $keyDeriver = null
    ) {
        if (null === $transformFactory) {
            $transformFactory = PasswordDecryptTransformFactory::instance();
        }
        if (null === $keyDeriver) {
            $keyDeriver = KeyDeriver::instance();
        }

        $this->transformFactory = $transformFactory;
        $this->keyDeriver = $keyDeriver;
    }

    /**
     * Get the transform factory.
     *
     * @return PasswordDecryptTransformFactoryInterface The transform factory.
     */
    public function transformFactory()
    {
        return $this->transformFactory;
    }

    /**
     * Get the key deriver.
     *
     * @return KeyDeriverInterface The key deriver.
     */
    public function keyDeriver()
    {
        return $this->keyDeriver;
    }

    /**
     * Decrypt a data packet.
     *
     * @param string $password The password to decrypt with.
     * @param string $data     The data to decrypt.
     *
     * @return tuple<string,integer>             A 2-tuple of the decrypted data, and the number of iterations used.
     * @throws PasswordDecryptionFailedException If the decryption failed.
     */
    public function decrypt($password, $data)
    {
        $size = strlen($data);
        if ($size < 118) {
            throw new PasswordDecryptionFailedException($password);
        }

        $version = ord(substr($data, 0, 1));
        if (1 !== $version) {
            throw new PasswordDecryptionFailedException(
                $password,
                new UnsupportedVersionException($version)
            );
        }

        $type = ord(substr($data, 1, 1));
        if (2 !== $type) {
            throw new PasswordDecryptionFailedException(
                $password,
                new UnsupportedTypeException($type)
            );
        }

        $iterations = unpack('N', substr($data, 2, 4));
        $iterations = array_shift($iterations);

        list($key) = $this->keyDeriver()->deriveKeyFromPassword(
            $password,
            $iterations,
            substr($data, 6, 64)
        );

        $hash = hash_hmac(
            'sha' . $key->authenticationSecretBits(),
            substr($data, 0, $size - $key->authenticationSecretBytes()),
            $key->authenticationSecret(),
            true
        );

        if (
            substr($data, $size - $key->authenticationSecretBytes()) !== $hash
        ) {
            throw new PasswordDecryptionFailedException($password);
        }

        $data = mcrypt_decrypt(
            MCRYPT_RIJNDAEL_128,
            $key->encryptionSecret(),
            substr($data, 86, $size - 118),
            MCRYPT_MODE_CBC,
            substr($data, 70, 16)
        );

        try {
            $data = $this->unpad($data);
        } catch (InvalidPaddingException $e) {
            throw new PasswordDecryptionFailedException($password, $e);
        }

        return array($data, $iterations);
    }

    /**
     * Create a new decrypt stream.
     *
     * @param string $password The password to decrypt with.
     *
     * @return TransformStreamInterface The newly created decrypt stream.
     */
    public function createDecryptStream($password)
    {
        return new TransformStream(
            $this->transformFactory()->createTransform($password)
        );
    }

    /**
     * Remove PKCS #7 (RFC 5652) padding from the supplied data.
     *
     * @link http://tools.ietf.org/html/rfc5652#section-6.3
     *
     * @param string $data The padded data.
     *
     * @return string                  The data with padding removed.
     * @throws InvalidPaddingException If the padding is invalid.
     */
    protected function unpad($data)
    {
        $padSize = ord(substr($data, -1));
        $padding = substr($data, -$padSize);

        if (str_repeat(chr($padSize), $padSize) !== $padding) {
            throw new InvalidPaddingException;
        }

        return substr($data, 0, -$padSize);
    }

    private static $instance;
    private $transformFactory;
    private $keyDeriver;
}
