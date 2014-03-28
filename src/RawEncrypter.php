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

use Eloquent\Lockbox\Random\DevUrandom;
use Eloquent\Lockbox\Random\RandomSourceInterface;

/**
 * Encrypts data and produces raw output.
 */
class RawEncrypter implements EncrypterInterface
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
     * Construct a new raw encrypter.
     *
     * @param RandomSourceInterface|null $randomSource The random source to use.
     */
    public function __construct(RandomSourceInterface $randomSource = null)
    {
        if (null === $randomSource) {
            $randomSource = DevUrandom::instance();
        }

        $this->randomSource = $randomSource;
        $this->version = $this->type = chr(1);
    }

    /**
     * Get the random source.
     *
     * @return RandomSourceInterface The random source.
     */
    public function randomSource()
    {
        return $this->randomSource;
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
        $iv = $this->randomSource()->generate(16);
        $ciphertext = $this->encryptAes($key, $iv, $data);

        return $this->version . $this->type . $iv . $ciphertext .
            $this->authenticationCode(
                $key, $this->version . $this->type . $iv . $ciphertext
            );
    }

    /**
     * Encrypt some data with AES and PKCS #7 padding.
     *
     * @param Key\KeyInterface $key  The key to encrypt with.
     * @param string           $iv   The initialization vector to use.
     * @param string           $data The data to encrypt.
     *
     * @return string The encrypted data.
     */
    protected function encryptAes(Key\KeyInterface $key, $iv, $data)
    {
        return mcrypt_encrypt(
            MCRYPT_RIJNDAEL_128,
            $key->encryptionSecret(),
            $this->pad($data),
            MCRYPT_MODE_CBC,
            $iv
        );
    }

    /**
     * Pad a string using PKCS #7 (RFC 2315) padding.
     *
     * @link http://tools.ietf.org/html/rfc2315
     *
     * @param string $data The data to pad.
     *
     * @return string The padded data.
     */
    protected function pad($data)
    {
        $padSize = intval(16 - (strlen($data) % 16));

        return $data . str_repeat(chr($padSize), $padSize);
    }

    /**
     * Create a message authentication code for the supplied ciphertext using
     * HMAC-SHA-256.
     *
     * @link https://tools.ietf.org/html/rfc6234
     *
     * @param KeyInterface $key        The key to authenticate with.
     * @param string       $ciphertext The ciphertext.
     *
     * @return string The message authentication code.
     */
    protected function authenticationCode(Key\KeyInterface $key, $ciphertext)
    {
        return hash_hmac(
            'sha' . $key->authenticationSecretBits(),
            $ciphertext,
            $key->authenticationSecret(),
            true
        );
    }

    private static $instance;
    private $randomSource;
    private $version;
    private $type;
}
