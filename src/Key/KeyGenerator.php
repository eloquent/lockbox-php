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
     * @param string|null  $name                     The name.
     * @param string|null  $description              The description.
     * @param integer|null $encryptionSecretBits     The size of the encryption secret in bits.
     * @param integer|null $authenticationSecretBits The size of the authentication secret in bits.
     *
     * @return KeyInterface                           The generated key.
     * @throws Exception\InvalidKeyExceptionInterface If the supplied arguments are invalid.
     */
    public function generateKey(
        $name = null,
        $description = null,
        $encryptionSecretBits = null,
        $authenticationSecretBits = null
    ) {
        if (null === $encryptionSecretBits) {
            $encryptionSecretBits = 256;
        }
        if (null === $authenticationSecretBits) {
            $authenticationSecretBits = 256;
        }

        switch ($encryptionSecretBits) {
            case 256:
            case 192:
            case 128:
                break;

            default:
                throw new Exception\InvalidEncryptionSecretSizeException(
                    $encryptionSecretBits
                );
        }

        switch ($authenticationSecretBits) {
            case 512:
            case 384:
            case 256:
            case 224:
                break;

            default:
                throw new Exception\InvalidAuthenticationSecretSizeException(
                    $authenticationSecretBits
                );
        }

        return $this->factory()->createKey(
            $this->randomSource()->generate($encryptionSecretBits / 8),
            $this->randomSource()->generate($authenticationSecretBits / 8),
            $name,
            $description
        );
    }

    private static $instance;
    private $factory;
    private $randomSource;
}
