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
use Eloquent\Endec\EncoderInterface;

/**
 * Encrypts data and produces encoded output using passwords.
 */
class PasswordEncrypter implements PasswordEncrypterInterface
{
    /**
     * Get the static instance of this encrypter.
     *
     * @return PasswordEncrypterInterface The static encrypter.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new password encrypter.
     *
     * @param PasswordEncrypterInterface|null $rawEncrypter The raw encrypter to use.
     * @param EncoderInterface|null           $encoder      The encoder to use.
     */
    public function __construct(
        PasswordEncrypterInterface $rawEncrypter = null,
        EncoderInterface $encoder = null
    ) {
        if (null === $rawEncrypter) {
            $rawEncrypter = RawPasswordEncrypter::instance();
        }
        if (null === $encoder) {
            $encoder = Base64Url::instance();
        }

        $this->rawEncrypter = $rawEncrypter;
        $this->encoder = $encoder;
    }

    /**
     * Get the raw encrypter.
     *
     * @return PasswordEncrypterInterface The raw encrypter.
     */
    public function rawEncrypter()
    {
        return $this->rawEncrypter;
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
     * Encrypt a data packet.
     *
     * @param string  $password   The password to encrypt with.
     * @param integer $iterations The number of hash iterations to use.
     * @param string  $data       The data to encrypt.
     *
     * @return string The encrypted data.
     */
    public function encrypt($password, $iterations, $data)
    {
        return $this->encoder()->encode(
            $this->rawEncrypter()->encrypt($password, $iterations, $data)
        );
    }

    /**
     * Create a new encrypt stream.
     *
     * @param string  $password   The password to encrypt with.
     * @param integer $iterations The number of hash iterations to use.
     *
     * @return TransformStreamInterface The newly created encrypt stream.
     */
    public function createEncryptStream($password, $iterations)
    {
        return $this->rawEncrypter()
            ->createEncryptStream($password, $iterations);
    }

    private static $instance;
    private $rawEncrypter;
    private $encoder;
}
