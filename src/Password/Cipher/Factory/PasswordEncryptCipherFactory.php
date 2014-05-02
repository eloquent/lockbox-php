<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Password\Cipher\Factory;

use Eloquent\Lockbox\Key\KeyDeriver;
use Eloquent\Lockbox\Key\KeyDeriverInterface;
use Eloquent\Lockbox\Password\Cipher\PasswordEncryptCipher;
use Eloquent\Lockbox\Random\DevUrandom;
use Eloquent\Lockbox\Random\RandomSourceInterface;

/**
 * Creates password encrypt ciphers.
 */
class PasswordEncryptCipherFactory implements
    PasswordEncryptCipherFactoryInterface
{
    /**
     * Get the static instance of this factory.
     *
     * @return PasswordEncryptCipherFactoryInterface The static factory.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new password encrypt cipher factory.
     *
     * @param KeyDeriverInterface|null   $keyDeriver   The key deriver to use.
     * @param RandomSourceInterface|null $randomSource The random source to use.
     */
    public function __construct(
        KeyDeriverInterface $keyDeriver = null,
        RandomSourceInterface $randomSource = null
    ) {
        if (null === $keyDeriver) {
            $keyDeriver = KeyDeriver::instance();
        }
        if (null === $randomSource) {
            $randomSource = DevUrandom::instance();
        }

        $this->keyDeriver = $keyDeriver;
        $this->randomSource = $randomSource;
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
     * Get the random source.
     *
     * @return RandomSourceInterface The random source.
     */
    public function randomSource()
    {
        return $this->randomSource;
    }

    /**
     * Create a new password encrypt cipher.
     *
     * @param string      $password   The password to encrypt with.
     * @param integer     $iterations The number of hash iterations to use.
     * @param string|null $salt       The salt to use for key derivation, or null to generate one.
     * @param string|null $iv         The initialization vector to use, or null to generate one.
     *
     * @return CipherInterface The newly created cipher.
     */
    public function createPasswordEncryptCipher(
        $password,
        $iterations,
        $salt = null,
        $iv = null
    ) {
        if (null === $salt) {
            $salt = $this->randomSource()->generate(64);
        }
        if (null === $iv) {
            $iv = $this->randomSource()->generate(16);
        }

        return new PasswordEncryptCipher(
            $password,
            $iterations,
            $salt,
            $iv,
            $this->keyDeriver()
        );
    }

    private static $instance;
    private $keyDeriver;
    private $randomSource;
}
