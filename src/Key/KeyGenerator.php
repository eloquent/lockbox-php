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
        KeyFactoryInterface $factory = null,
        RandomSourceInterface $randomSource = null
    ) {
        if (null === $factory) {
            $factory = KeyFactory::instance();
        }
        if (null === $randomSource) {
            $randomSource = DevUrandom::instance();
        }

        $this->factory = $factory;
        $this->randomSource = $randomSource;
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
     * Get the random source.
     *
     * @return RandomSourceInterface The random source.
     */
    public function randomSource()
    {
        return $this->randomSource;
    }

    /**
     * Generate a new key.
     *
     * @param integer|null $encryptionSecretSize     The size of the encryption secret in bits.
     * @param integer|null $authenticationSecretSize The size of the authentication secret in bits.
     * @param string|null  $name                     The name.
     * @param string|null  $description              The description.
     *
     * @return KeyInterface                      The generated key.
     * @throws Exception\InvalidKeySizeException If the requested key size is invalid.
     */
    public function generateKey(
        $encryptionSecretSize = null,
        $authenticationSecretSize = null,
        $name = null,
        $description = null
    ) {
        if (null === $encryptionSecretSize) {
            $encryptionSecretSize = 256;
        }
        if (null === $authenticationSecretSize) {
            $authenticationSecretSize = 256;
        }

        switch ($encryptionSecretSize) {
            case 256:
            case 192:
            case 128:
                break;

            default:
                throw new Exception\InvalidEncryptionSecretSizeException(
                    $encryptionSecretSize
                );
        }

        switch ($authenticationSecretSize) {
            case 512:
            case 384:
            case 256:
            case 224:
                break;

            default:
                throw new Exception\InvalidAuthenticationSecretSizeException(
                    $authenticationSecretSize
                );
        }

        return $this->factory()->createKey(
            $this->randomSource()->generate($encryptionSecretSize / 8),
            $this->randomSource()->generate($authenticationSecretSize / 8),
            $name,
            $description
        );
    }

    private static $instance;
    private $factory;
    private $randomSource;
}
