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
use Eloquent\Lockbox\Key\KeyInterface;
use Eloquent\Lockbox\Random\DevUrandom;
use Eloquent\Lockbox\Random\RandomSourceInterface;
use Eloquent\Lockbox\Transform\EncryptTransform;

/**
 * Creates encrypt transforms.
 */
class EncryptTransformFactory implements CryptographicTransformFactoryInterface
{
    /**
     * Get the static instance of this factory.
     *
     * @return EncrypterInterface The static factory.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new encrypt data transform.
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
     * Create a new transform for the supplied key.
     *
     * @param KeyInterface $key The key to use.
     *
     * @return DataTransformInterface The newly created transform.
     */
    public function createTransform(KeyInterface $key)
    {
        return new EncryptTransform($key, $this->randomSource());
    }

    private static $instance;
    private $randomSource;
}
