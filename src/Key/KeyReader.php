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
use Exception as NativeException;
use Icecave\Isolator\Isolator;

/**
 * Reads encryption keys from files and streams.
 */
class KeyReader implements KeyReaderInterface
{
    /**
     * Get the static instance of this reader.
     *
     * @return KeyReaderInterface The static reader.
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
     * @param KeyFactoryInterface|null $factory  The factory to use.
     * @param DecoderInterface|null    $decoder  The decoder to use.
     * @param Isolator|null            $isolator The isolator to use.
     */
    public function __construct(
        KeyFactoryInterface $factory = null,
        DecoderInterface $decoder = null,
        Isolator $isolator = null
    ) {
        if (null === $factory) {
            $factory = KeyFactory::instance();
        }
        if (null === $decoder) {
            $decoder = Base64Url::instance();
        }

        $this->factory = $factory;
        $this->decoder = $decoder;
        $this->isolator = Isolator::get($isolator);
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
     * @return KeyInterface               The key.
     * @throws Exception\KeyReadException If the key cannot be read, or if the key is invalid.
     */
    public function readFile($path)
    {
        $stream = $this->isolator()->fopen($path, 'rb');
        if (false === $stream) {
            throw new Exception\KeyReadException($path);
        }

        $e = null;
        try {
            $key = $this->readStream($stream, $path);
        } catch (NativeException $e) {
            // re-thrown after cleanup
        }

        $this->isolator()->fclose($stream);

        if ($e) {
            throw $e;
        }

        return $key;
    }

    /**
     * Read a key from the supplied stream.
     *
     * @param stream      $stream The stream to read from.
     * @param string|null $path   The path, if known.
     *
     * @return KeyInterface               The key.
     * @throws Exception\KeyReadException If the key cannot be read, or if the key is invalid.
     */
    public function readStream($stream, $path = null)
    {
        $data = @stream_get_contents($stream);
        if (!$data) {
            throw new Exception\KeyReadException($path);
        }

        return $this->readString($data, $path);
    }

    /**
     * Read a key from the supplied string.
     *
     * @param string      $data The string to read from.
     * @param string|null $path The path, if known.
     *
     * @return KeyInterface               The key.
     * @throws Exception\KeyReadException If the key cannot be read, or if the key is invalid.
     */
    public function readString($data, $path = null)
    {
        $data = json_decode($data);
        if (JSON_ERROR_NONE !== json_last_error()) {
            throw new Exception\KeyReadException($path);
        }

        $type = null;
        if (isset($data->type)) {
            $type = $data->type;
        }
        if ('lockbox-key' !== $type) {
            throw new Exception\KeyReadException($path);
        }

        $version = null;
        if (isset($data->version)) {
            $version = $data->version;
        }
        if (1 !== $version) {
            throw new Exception\KeyReadException($path);
        }

        $encryptionSecret = null;
        if (isset($data->encryptionSecret)) {
            try {
                $encryptionSecret = $this->decoder()
                    ->decode($data->encryptionSecret);
            } catch (EncodingExceptionInterface $e) {
                throw new Exception\KeyReadException($path, $e);
            }
        }
        if (!$encryptionSecret) {
            throw new Exception\KeyReadException($path);
        }

        $authenticationSecret = null;
        if (isset($data->authenticationSecret)) {
            try {
                $authenticationSecret = $this->decoder()
                    ->decode($data->authenticationSecret);
            } catch (EncodingExceptionInterface $e) {
                throw new Exception\KeyReadException($path, $e);
            }
        }
        if (!$authenticationSecret) {
            throw new Exception\KeyReadException($path);
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
        } catch (Exception\InvalidKeyExceptionInterface $e) {
            throw new Exception\KeyReadException($path, $e);
        }

        return $key;
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

    private static $instance;
    private $factory;
    private $decoder;
    private $isolator;
}
