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

use Eloquent\Lockbox\Cipher\CipherInterface;
use Eloquent\Lockbox\Cipher\Factory\CipherFactoryInterface;
use Eloquent\Lockbox\Key\KeyDeriver;
use Eloquent\Lockbox\Key\KeyDeriverInterface;
use Eloquent\Lockbox\Padding\PadderInterface;
use Eloquent\Lockbox\Padding\PkcsPadding;
use Eloquent\Lockbox\Password\Cipher\PasswordEncryptCipher;
use Eloquent\Lockbox\Random\DevUrandom;
use Eloquent\Lockbox\Random\RandomSourceInterface;

/**
 * Creates encrypt ciphers that use passwords.
 */
class PasswordEncryptCipherFactory implements CipherFactoryInterface
{
    /**
     * Get the static instance of this factory.
     *
     * @return CipherFactoryInterface The static factory.
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
     * @param RandomSourceInterface|null $randomSource The random source to use.
     * @param KeyDeriverInterface|null   $keyDeriver   The key deriver to use.
     * @param PadderInterface|null       $padder       The padder to use.
     */
    public function __construct(
        RandomSourceInterface $randomSource = null,
        KeyDeriverInterface $keyDeriver = null,
        PadderInterface $padder = null
    ) {
        if (null === $keyDeriver) {
            $keyDeriver = KeyDeriver::instance();
        }
        if (null === $randomSource) {
            $randomSource = DevUrandom::instance();
        }
        if (null === $padder) {
            $padder = PkcsPadding::instance();
        }

        $this->randomSource = $randomSource;
        $this->keyDeriver = $keyDeriver;
        $this->padder = $padder;
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
     * Get the key deriver.
     *
     * @return KeyDeriverInterface The key deriver.
     */
    public function keyDeriver()
    {
        return $this->keyDeriver;
    }

    /**
     * Get the padder.
     *
     * @return PadderInterface The padder.
     */
    public function padder()
    {
        return $this->padder;
    }

    /**
     * Create a new cipher.
     *
     * @return CipherInterface The newly created cipher.
     */
    public function createCipher()
    {
        return new PasswordEncryptCipher(
            $this->randomSource(),
            $this->keyDeriver(),
            $this->padder()
        );
    }

    private static $instance;
    private $randomSource;
    private $keyDeriver;
    private $padder;
}
