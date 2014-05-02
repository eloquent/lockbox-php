<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Cipher\Factory;

use Eloquent\Lockbox\Cipher\EncryptCipher;
use Eloquent\Lockbox\Key\KeyInterface;
use Eloquent\Lockbox\Random\DevUrandom;
use Eloquent\Lockbox\Random\RandomSourceInterface;

/**
 * Creates encrypt ciphers.
 */
class EncryptCipherFactory implements EncryptCipherFactoryInterface
{
    /**
     * Get the static instance of this factory.
     *
     * @return EncryptCipherFactoryInterface The static factory.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new encrypt cipher factory.
     *
     * @param RandomSourceInterface|null $randomSource The random source to use.
     */
    public function __construct(RandomSourceInterface $randomSource = null)
    {
        if (null === $randomSource) {
            $randomSource = DevUrandom::instance();
        }

        $this->randomSource = $randomSource;
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
     * Create a new encrypt cipher.
     *
     * @param KeyInterface $key The key to encrypt with.
     * @param string|null  $iv  The initialization vector to use, or null to generate one.
     *
     * @return CipherInterface The newly created cipher.
     */
    public function createEncryptCipher(KeyInterface $key, $iv = null)
    {
        if (null === $iv) {
            $iv = $this->randomSource()->generate(16);
        }

        return new EncryptCipher($key, $iv);
    }

    private static $instance;
    private $randomSource;
}
