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

use Eloquent\Confetti\TransformStreamInterface;
use Eloquent\Endec\Base64\Base64Url;
use Eloquent\Lockbox\Exception\PasswordDecryptionFailedException;

/**
 * Decrypts encoded data using passwords.
 */
class PasswordDecrypter implements PasswordDecrypterInterface
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
     * Construct a new password decrypter.
     *
     * @param PasswordDecrypterInterface|null $rawDecrypter The raw decrypter to use.
     * @param DecoderInterface|null           $decoder      The decoder to use.
     */
    public function __construct(
        PasswordDecrypterInterface $rawDecrypter = null,
        DecoderInterface $decoder = null
    ) {
        if (null === $rawDecrypter) {
            $rawDecrypter = RawPasswordDecrypter::instance();
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
     * @return PasswordDecrypterInterface The raw decrypter.
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
     * @param string $password The password to decrypt with.
     * @param string $data     The data to decrypt.
     *
     * @return tuple<string,integer>             A 2-tuple of the decrypted data, and the number of iterations used.
     * @throws PasswordDecryptionFailedException If the decryption failed.
     */
    public function decrypt($password, $data)
    {
        try {
            $data = $this->decoder()->decode($data);
        } catch (EncodingExceptionInterface $e) {
            throw new PasswordDecryptionFailedException($password, $e);
        }

        return $this->rawDecrypter()->decrypt($password, $data);
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
        return $this->rawDecrypter()->createDecryptStream($password);
    }

    private static $instance;
    private $rawDecrypter;
    private $decoder;
}
