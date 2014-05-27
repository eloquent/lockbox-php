<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Key\Generator;

use Eloquent\Lockbox\Key\Exception\InvalidAuthSecretSizeException;
use Eloquent\Lockbox\Key\Exception\InvalidEncryptSecretSizeException;
use Eloquent\Lockbox\Key\Exception\InvalidKeyParameterExceptionInterface;
use Eloquent\Lockbox\Key\Factory\KeyFactory;
use Eloquent\Lockbox\Key\Factory\KeyFactoryInterface;
use Eloquent\Lockbox\Key\KeyInterface;
use Eloquent\Lockbox\Random\DevUrandom;
use Eloquent\Lockbox\Random\RandomSourceInterface;

/**
 * Generates encryption keys.
 */
class KeyGenerator implements KeyGeneratorInterface
{
    /**
     * Get the static instance of this generator.
     *
     * @return KeyGeneratorInterface The static generator.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new key generator.
     *
     * @param KeyFactoryInterface|null   $factory      The factory to use.
     * @param RandomSourceInterface|null $randomSource The random source to use.
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
     * Generate a new key.
     *
     * @param string|null  $name              The name.
     * @param string|null  $description       The description.
     * @param integer|null $encryptSecretBits The size of the encrypt secret in bits.
     * @param integer|null $authSecretBits    The size of the auth secret in bits.
     *
     * @return KeyInterface                          The generated key.
     * @throws InvalidKeyParameterExceptionInterface If the supplied arguments are invalid.
     */
    public function generateKey(
        $name = null,
        $description = null,
        $encryptSecretBits = null,
        $authSecretBits = null
    ) {
        if (null === $encryptSecretBits) {
            $encryptSecretBits = 256;
        }
        if (null === $authSecretBits) {
            $authSecretBits = 256;
        }

        switch ($encryptSecretBits) {
            case 256:
            case 192:
            case 128:
                break;

            default:
                throw new InvalidEncryptSecretSizeException($encryptSecretBits);
        }

        switch ($authSecretBits) {
            case 512:
            case 384:
            case 256:
            case 224:
                break;

            default:
                throw new InvalidAuthSecretSizeException($authSecretBits);
        }

        return $this->factory()->createKey(
            $this->randomSource()->generate($encryptSecretBits / 8),
            $this->randomSource()->generate($authSecretBits / 8),
            $name,
            $description
        );
    }

    private static $instance;
    private $randomSource;
    private $factory;
}
