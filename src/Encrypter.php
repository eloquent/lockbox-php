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
use Eloquent\Endec\EncoderInterface;

/**
 * Encrypts data and produces encoded output.
 */
class Encrypter implements EncrypterInterface
{
    /**
     * Get the static instance of this encrypter.
     *
     * @return EncrypterInterface The static encrypter.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new encrypter.
     *
     * @param EncrypterInterface|null $rawEncrypter The raw encrypter to use.
     * @param EncoderInterface|null   $encoder      The encoder to use.
     */
    public function __construct(
        EncrypterInterface $rawEncrypter = null,
        EncoderInterface $encoder = null
    ) {
        if (null === $rawEncrypter) {
            $rawEncrypter = RawEncrypter::instance();
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
     * @return EncrypterInterface The raw encrypter.
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
     * @param Key\KeyInterface $key  The key to encrypt with.
     * @param string           $data The data to encrypt.
     *
     * @return string The encrypted data.
     */
    public function encrypt(Key\KeyInterface $key, $data)
    {
        return $this->encoder()
            ->encode($this->rawEncrypter()->encrypt($key, $data));
    }

    private static $instance;
    private $rawEncrypter;
    private $encoder;
}
