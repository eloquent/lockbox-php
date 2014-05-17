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

use Eloquent\Lockbox\Key\Exception\InvalidIterationsException;
use Eloquent\Lockbox\Key\Exception\InvalidKeyParameterExceptionInterface;
use Eloquent\Lockbox\Key\Exception\InvalidSaltException;
use Eloquent\Lockbox\Key\Exception\InvalidSaltSizeException;
use Eloquent\Lockbox\Password\PasswordInterface;
use Eloquent\Lockbox\Random\DevUrandom;
use Eloquent\Lockbox\Random\RandomSourceInterface;

/**
 * Derives keys from various data sources.
 */
class KeyDeriver implements KeyDeriverInterface
{
    /**
     * Get the static instance of this deriver.
     *
     * @return KeyDeriverInterface The static deriver.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new key deriver.
     *
     * @param RandomSourceInterface|null $randomSource The random source to use.
     * @param KeyFactoryInterface|null   $factory      The factory to use.
     */
    public function __construct(
        RandomSourceInterface $randomSource = null,
        KeyFactoryInterface $factory = null
    ) {
        if (null === $randomSource) {
            $randomSource = DevUrandom::instance();
        }
        if (null === $factory) {
            $factory = KeyFactory::instance();
        }

        $this->randomSource = $randomSource;
        $this->factory = $factory;
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
     * Get the factory.
     *
     * @return KeyFactoryInterface The factory.
     */
    public function factory()
    {
        return $this->factory;
    }

    /**
     * Derive a key from a password.
     *
     * @param PasswordInterface $password    The password.
     * @param integer           $iterations  The number of hash iterations to use.
     * @param string|null       $salt        The salt to use, or null to generate a random salt.
     * @param string|null       $name        The name.
     * @param string|null       $description The description.
     *
     * @return tuple<KeyInterface,string>            A 2-tuple of the derived key, and the salt used.
     * @throws InvalidKeyParameterExceptionInterface If the supplied arguments are invalid.
     */
    public function deriveKeyFromPassword(
        PasswordInterface $password,
        $iterations,
        $salt = null,
        $name = null,
        $description = null
    ) {
        if (!is_int($iterations) || $iterations < 1) {
            throw new InvalidIterationsException($iterations);
        }

        if (null === $salt) {
            $salt = $this->randomSource()->generate(64);
        } else {
            if (!is_string($salt)) {
                throw new InvalidSaltException($salt);
            }

            $saltSize = strlen($salt);
            if (64 !== $saltSize) {
                throw new InvalidSaltSizeException($saltSize * 8);
            }
        }

        list($encryptionSecret, $authenticationSecret) = str_split(
            hash_pbkdf2(
                'sha512',
                $password->string(),
                $salt,
                $iterations,
                64,
                true
            ),
            32
        );

        return array(
            $this->factory()->createKey(
                $encryptionSecret,
                $authenticationSecret,
                $name,
                $description
            ),
            $salt,
        );
    }

    private static $instance;
    private $randomSource;
    private $factory;
}
