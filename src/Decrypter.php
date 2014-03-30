<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox;

use Eloquent\Endec\Base64\Base64Url;
use Eloquent\Endec\DecoderInterface;
use Eloquent\Endec\Transform\Exception\TransformExceptionInterface;
use Eloquent\Endec\Transform\TransformStreamInterface;

/**
 * Decrypts encoded data using keys.
 */
class Decrypter implements DecrypterInterface
{
    /**
     * Get the static instance of this decrypter.
     *
     * @return DecrypterInterface The static decrypter.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new decrypter.
     *
     * @param DecrypterInterface|null $rawDecrypter The raw decrypter to use.
     * @param DecoderInterface|null   $decoder      The decoder to use.
     */
    public function __construct(
        DecrypterInterface $rawDecrypter = null,
        DecoderInterface $decoder = null
    ) {
        if (null === $rawDecrypter) {
            $rawDecrypter = RawDecrypter::instance();
        }
        if (null === $decoder) {
            $decoder = Base64Url::instance();
        }

        $this->rawDecrypter = $rawDecrypter;
        $this->decoder = $decoder;
    }

    /**
     * Get the raw decrypter.
     *
     * @return DecrypterInterface The raw decrypter.
     */
    public function rawDecrypter()
    {
        return $this->rawDecrypter;
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
     * Decrypt a data packet.
     *
     * @param Key\KeyInterface $key  The key to decrypt with.
     * @param string           $data The data to decrypt.
     *
     * @return string                              The decrypted data.
     * @throws Exception\DecryptionFailedException If the decryption failed.
     */
    public function decrypt(Key\KeyInterface $key, $data)
    {
        try {
            $data = $this->decoder()->decode($data);
        } catch (TransformExceptionInterface $e) {
            throw new Exception\DecryptionFailedException($key, $e);
        }

        return $this->rawDecrypter()->decrypt($key, $data);
    }

    /**
     * Create a new decrypt stream.
     *
     * @param Key\KeyInterface $key The key to decrypt with.
     *
     * @return TransformStreamInterface The newly created decrypt stream.
     */
    public function createDecryptStream(Key\KeyInterface $key)
    {
        return $this->rawDecrypter()->createDecryptStream($key);
    }

    private static $instance;
    private $rawDecrypter;
    private $decoder;
}
