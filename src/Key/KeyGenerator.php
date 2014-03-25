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

use Icecave\Isolator\Isolator;

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
     * @param KeyFactoryInterface|null $factory      The factory to use.
     * @param integer|null             $randomSource The random source to use.
     * @param Isolator|null            $isolator     The isolator to use.
     */
    public function __construct(
        KeyFactoryInterface $factory = null,
        $randomSource = null,
        Isolator $isolator = null
    ) {
        if (null === $factory) {
            $factory = KeyFactory::instance();
        }
        if (null === $randomSource) {
            $randomSource = MCRYPT_DEV_URANDOM;
        }

        $this->factory = $factory;
        $this->randomSource = $randomSource;
        $this->isolator = Isolator::get($isolator);
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
     * @return integer The random source.
     */
    public function randomSource()
    {
        return $this->randomSource;
    }

    /**
     * Generate a new key.
     *
     * @param integer|null $size        The size of the key in bits.
     * @param string|null  $name        The name.
     * @param string|null  $description The description.
     *
     * @return KeyInterface                      The generated key.
     * @throws Exception\InvalidKeySizeException If the requested key size is invalid.
     */
    public function generateKey($size = null, $name = null, $description = null)
    {
        if (null === $size) {
            $size = 256;
        }

        switch ($size) {
            case 256:
            case 192:
            case 128:
                break;

            default:
                throw new Exception\InvalidKeySizeException($size);
        }

        return $this->factory()->createKey(
            $this->isolator()
                ->mcrypt_create_iv($size / 8, $this->randomSource()),
            $name,
            $description
        );
    }

    /**
     * Get the isolator.
     *
     * @return Isolator The isolator.
     */
    protected function isolator()
    {
        return $this->isolator;
    }

    private static $instance;
    private $factory;
    private $randomSource;
    private $isolator;
}
