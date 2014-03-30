<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Transform\Factory;

use Eloquent\Endec\Transform\DataTransformInterface;
use Eloquent\Lockbox\Key\KeyDeriver;
use Eloquent\Lockbox\Key\KeyDeriverInterface;
use Eloquent\Lockbox\Random\DevUrandom;
use Eloquent\Lockbox\Random\RandomSourceInterface;
use Eloquent\Lockbox\Transform\PasswordEncryptTransform;

/**
 * Creates encrypt transforms that use passwords.
 */
class PasswordEncryptTransformFactory implements
    PasswordEncryptTransformFactoryInterface
{
    /**
     * Get the static instance of this factory.
     *
     * @return PasswordEncryptTransformFactoryInterface The static factory.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new password encrypt transform factory.
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
     * Create a new transform for the supplied password.
     *
     * @param string  $password   The password to use.
     * @param integer $iterations The number of hash iterations to use.
     *
     * @return DataTransformInterface The newly created transform.
     */
    public function createTransform($password, $iterations)
    {
        return new PasswordEncryptTransform(
            $password,
            $iterations,
            $this->keyDeriver(),
            $this->randomSource()
        );
    }

    private static $instance;
    private $keyDeriver;
    private $randomSource;
}
