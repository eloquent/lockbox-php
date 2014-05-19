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

use Eloquent\Endec\Base64\Base64Url;
use Eloquent\Endec\DecoderInterface;
use Eloquent\Endec\Exception\EncodingExceptionInterface;
use Eloquent\Lockbox\Comparator\SlowStringComparator;
use Eloquent\Lockbox\DecrypterInterface;
use Eloquent\Lockbox\Key\Exception\InvalidKeyParameterExceptionInterface;
use Eloquent\Lockbox\Key\Exception\KeyReadException;
use Eloquent\Lockbox\Password\Password;
use Eloquent\Lockbox\Password\PasswordDecrypter;
use Eloquent\Lockbox\Password\PasswordInterface;
use Icecave\Isolator\Isolator;

/**
 * Reads encryption keys from files and streams.
 */
class KeyReader implements EncryptedKeyReaderInterface
{
    /**
     * Get the static instance of this reader.
     *
     * @return EncryptedKeyReaderInterface The static reader.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new key reader.
     *
     * @param KeyFactoryInterface|null $factory   The factory to use.
     * @param DecrypterInterface|null  $decrypter The decrypter to use.
     * @param DecoderInterface|null    $decoder   The decoder to use.
     * @param Isolator|null            $isolator  The isolator to use.
     */
    public function __construct(
        KeyFactoryInterface $factory = null,
        DecrypterInterface $decrypter = null,
        DecoderInterface $decoder = null,
        Isolator $isolator = null
    ) {
        if (null === $factory) {
            $factory = KeyFactory::instance();
        }
        if (null === $decrypter) {
            $decrypter = PasswordDecrypter::instance();
        }
        if (null === $decoder) {
            $decoder = Base64Url::instance();
        }

        $this->factory = $factory;
        $this->decrypter = $decrypter;
        $this->decoder = $decoder;
        $this->isolator = Isolator::get($isolator);
        $this->encryptedHeader = chr(1) . chr(2);
    }

    /**
     * Get the factory.
     *
     * @return KeyFactoryInterface The factory.
     */
    public function factory()
    {
        return $this->factory;
    }

    /**
     * Get the decrypter.
     *
     * @return DecrypterInterface The decrypter.
     */
    public function decrypter()
    {
        return $this->decrypter;
    }

    /**
     * Get the decoder.
     *
     * @return DecoderInterface The decoder.
     */
    public function decoder()
    {
        return $this->decoder;
    }

    /**
     * Read a key from the supplied path.
     *
     * @param string $path The path to read from.
     *
     * @return KeyInterface     The key.
     * @throws KeyReadException If the key cannot be read, or if the key is invalid.
     */
    public function readFile($path)
    {
        if (!$data = @$this->isolator()->file_get_contents($path)) {
            throw new KeyReadException($path);
        }

        return $this->readString($data, $path);
    }

    /**
     * Read a key from the supplied path, and decrypt with a password.
     *
     * @param PasswordInterface $password The password.
     * @param string            $path     The path to read from.
     *
     * @return KeyInterface     The key.
     * @throws KeyReadException If the key cannot be read, or if the key is invalid.
     */
    public function readFileWithPassword(PasswordInterface $password, $path)
    {
        if (!$data = @$this->isolator()->file_get_contents($path)) {
            throw new KeyReadException($path);
        }

        return $this->readStringWithPassword($password, $data, $path);
    }

    /**
     * Read a key from the supplied path, and decrypt with an optional password.
     *
     * If a password is required to read the key, it will be acquired by
     * executing the callback.
     *
     * @param callable $callback The password callback.
     * @param string   $path     The path to read from.
     *
     * @return KeyInterface     The key.
     * @throws KeyReadException If the key cannot be read, or if the key is invalid.
     */
    public function readFileWithPasswordCallback($callback, $path)
    {
        if (!$data = @$this->isolator()->file_get_contents($path)) {
            throw new KeyReadException($path);
        }

        return $this->readStringWithPasswordCallback($callback, $data, $path);
    }

    /**
     * Read a key from the supplied stream.
     *
     * @param stream      $stream The stream to read from.
     * @param string|null $path   The path, if known.
     *
     * @return KeyInterface     The key.
     * @throws KeyReadException If the key cannot be read, or if the key is invalid.
     */
    public function readStream($stream, $path = null)
    {
        if (!$data = @stream_get_contents($stream)) {
            throw new KeyReadException($path);
        }

        return $this->readString($data, $path);
    }

    /**
     * Read a key from the supplied stream, and decrypt with a password.
     *
     * @param PasswordInterface $password The password.
     * @param stream            $stream   The stream to read from.
     * @param string|null       $path     The path, if known.
     *
     * @return KeyInterface     The key.
     * @throws KeyReadException If the key cannot be read, or if the key is invalid.
     */
    public function readStreamWithPassword(
        PasswordInterface $password,
        $stream,
        $path = null
    ) {
        if (!$data = @stream_get_contents($stream)) {
            throw new KeyReadException($path);
        }

        return $this->readStringWithPassword($password, $data, $path);
    }

    /**
     * Read a key from the supplied stream, and decrypt with an optional
     * password.
     *
     * If a password is required to read the key, it will be acquired by
     * executing the callback.
     *
     * @param callable    $callback The password callback.
     * @param stream      $stream   The stream to read from.
     * @param string|null $path     The path, if known.
     *
     * @return KeyInterface     The key.
     * @throws KeyReadException If the key cannot be read, or if the key is invalid.
     */
    public function readStreamWithPasswordCallback(
        $callback,
        $stream,
        $path = null
    ) {
        if (!$data = @stream_get_contents($stream)) {
            throw new KeyReadException($path);
        }

        return $this->readStringWithPasswordCallback($callback, $data, $path);
    }

    /**
     * Read a key from the supplied string.
     *
     * @param string      $data The string to read from.
     * @param string|null $path The path, if known.
     *
     * @return KeyInterface     The key.
     * @throws KeyReadException If the key cannot be read, or if the key is invalid.
     */
    public function readString($data, $path = null)
    {
        $data = json_decode($data);
        if (JSON_ERROR_NONE !== json_last_error()) {
            throw new KeyReadException($path);
        }

        $type = null;
        if (isset($data->type)) {
            $type = $data->type;
        }
        if ('lockbox-key' !== $type) {
            throw new KeyReadException($path);
        }

        $version = null;
        if (isset($data->version)) {
            $version = $data->version;
        }
        if (1 !== $version) {
            throw new KeyReadException($path);
        }

        $encryptionSecret = null;
        if (isset($data->encryptionSecret)) {
            try {
                $encryptionSecret = $this->decoder()
                    ->decode($data->encryptionSecret);
            } catch (EncodingExceptionInterface $e) {
                throw new KeyReadException($path, $e);
            }
        }
        if (!$encryptionSecret) {
            throw new KeyReadException($path);
        }

        $authenticationSecret = null;
        if (isset($data->authenticationSecret)) {
            try {
                $authenticationSecret = $this->decoder()
                    ->decode($data->authenticationSecret);
            } catch (EncodingExceptionInterface $e) {
                throw new KeyReadException($path, $e);
            }
        }
        if (!$authenticationSecret) {
            throw new KeyReadException($path);
        }

        $name = null;
        if (isset($data->name)) {
            $name = $data->name;
        }

        $description = null;
        if (isset($data->description)) {
            $description = $data->description;
        }

        try {
            $key = new Key(
                $encryptionSecret,
                $authenticationSecret,
                $name,
                $description
            );
        } catch (InvalidKeyParameterExceptionInterface $e) {
            throw new KeyReadException($path, $e);
        }

        return $key;
    }

    /**
     * Read a key from the supplied string, and decrypt with a password.
     *
     * @param PasswordInterface $password The password.
     * @param string            $data     The string to read from.
     * @param string|null       $path     The path, if known.
     *
     * @return KeyInterface     The key.
     * @throws KeyReadException If the key cannot be read, or if the key is invalid.
     */
    public function readStringWithPassword(
        PasswordInterface $password,
        $data,
        $path = null
    ) {
        $result = $this->decrypter()->decrypt($password, trim($data));
        if (!$result->isSuccessful()) {
            throw new KeyReadException($path);
        }

        return $this->readString($result->data(), $path);
    }

    /**
     * Read a key from the supplied string, and decrypt with a password.
     *
     * @param callable    $callback The password callback.
     * @param string      $data     The string to read from.
     * @param string|null $path     The path, if known.
     *
     * @return KeyInterface     The key.
     * @throws KeyReadException If the key cannot be read, or if the key is invalid.
     */
    public function readStringWithPasswordCallback(
        $callback,
        $data,
        $path = null
    ) {
        $data = trim($data);

        if ($this->isEncryptedData($data)) {
            return $this->readStringWithPassword($callback(), $data, $path);
        }

        return $this->readString($data, $path);
    }

    /**
     * Get the isolator.
     *
     * @return Isolator The isolator.
     */
    protected function isolator()
    {
        return $this->isolator;
    }

    /**
     * Returns true if the supplied data appears to be a password encrypted
     * packet.
     *
     * @param string $data The data to check for encryption.
     *
     * @return boolean True if the data appears to be encrypted.
     */
    protected function isEncryptedData($data)
    {
        try {
            $data = $this->decoder()->decode($data);
        } catch (EncodingExceptionInterface $e) {
            return false;
        }

        return SlowStringComparator::isEqual(
            $this->encryptedHeader,
            substr($data, 0, 2)
        );
    }

    private static $instance;
    private $factory;
    private $decrypter;
    private $decoder;
    private $isolator;
    private $encryptedHeader;
}
