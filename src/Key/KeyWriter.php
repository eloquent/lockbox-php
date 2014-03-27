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
use Eloquent\Endec\EncoderInterface;
use Exception as NativeException;
use Icecave\Isolator\Isolator;
use stdClass;

/**
 * Writes encryption keys to files and streams.
 */
class KeyWriter implements KeyWriterInterface
{
    /**
     * Get the static instance of this writer.
     *
     * @return KeyWriterInterface The static writer.
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
     * @param EncoderInterface|null $encoder  The encoder to use.
     * @param Isolator|null         $isolator The isolator to use.
     */
    public function __construct(
        EncoderInterface $encoder = null,
        Isolator $isolator = null
    ) {
        if (null === $encoder) {
            $encoder = Base64Url::instance();
        }

        $this->encoder = $encoder;
        $this->isolator = Isolator::get($isolator);
    }

    /**
     * Get the encoder.
     *
     * @return EncoderInterface The encoder.
     */
    public function encoder()
    {
        return $this->encoder;
    }

    /**
     * Write a key to the supplied path.
     *
     * @param KeyInterface $key  The key.
     * @param string       $path The path to write to.
     *
     * @throws Exception\KeyWriteException If the key cannot be written.
     */
    public function writeFile(KeyInterface $key, $path)
    {
        $stream = @$this->isolator()->fopen($path, 'wb');
        if (false === $stream) {
            throw new Exception\KeyWriteException($path);
        }

        $e = null;
        try {
            $this->writeStream($key, $stream, $path);
        } catch (NativeException $e) {
            // re-thrown after cleanup
        }

        $this->isolator()->fclose($stream);

        if ($e) {
            throw $e;
        }
    }

    /**
     * Write a key to the supplied stream.
     *
     * @param KeyInterface $key    The key.
     * @param stream       $stream The stream to write to.
     * @param string|null  $path   The path, if known.
     *
     * @throws Exception\KeyWriteException If the key cannot be written.
     */
    public function writeStream(KeyInterface $key, $stream, $path = null)
    {
        $result = @fwrite($stream, json_encode($this->keyData($key)));
        if (!$result) {
            throw new Exception\KeyWriteException($path);
        }
    }

    /**
     * Create a JSON serializable object from the supplied key.
     *
     * @param KeyInterface $key The key.
     *
     * @return stdClass The serializable object.
     */
    protected function keyData(KeyInterface $key)
    {
        $data = new stdClass;
        $data->type = 'lockbox-key';
        $data->version = 1;

        if (null !== $key->name()) {
            $data->name = $key->name();
        }
        if (null !== $key->description()) {
            $data->description = $key->description();
        }

        $data->encryptionSecret = $this->encoder()
            ->encode($key->encryptionSecret());
        $data->authenticationSecret = $this->encoder()
            ->encode($key->authenticationSecret());

        return $data;
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
    private $encoder;
    private $isolator;
}
