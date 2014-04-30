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

use Eloquent\Confetti\TransformInterface;
use Eloquent\Lockbox\Cipher\Factory\EncryptCipherFactory;
use Eloquent\Lockbox\Cipher\Factory\EncryptCipherFactoryInterface;
use Eloquent\Lockbox\Key\KeyInterface;
use Eloquent\Lockbox\Transform\EncryptTransform;

/**
 * Creates encrypt transforms that use keys.
 */
class EncryptTransformFactory implements KeyTransformFactoryInterface
{
    /**
     * Get the static instance of this factory.
     *
     * @return KeyTransformFactoryInterface The static factory.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new encrypt transform factory.
     *
     * @param EncryptCipherFactoryInterface|null $cipherFactory The cipher factory to use.
     */
    public function __construct(
        EncryptCipherFactoryInterface $cipherFactory = null
    ) {
        if (null === $cipherFactory) {
            $cipherFactory = EncryptCipherFactory::instance();
        }

        $this->cipherFactory = $cipherFactory;
    }

    /**
     * Get the cipher factory.
     *
     * @return EncryptCipherFactoryInterface The cipher factory.
     */
    public function cipherFactory()
    {
        return $this->cipherFactory;
    }

    /**
     * Create a new transform for the supplied key.
     *
     * @param KeyInterface $key The key to use.
     *
     * @return TransformInterface The newly created transform.
     */
    public function createTransform(KeyInterface $key)
    {
        return new EncryptTransform(
            $this->cipherFactory()->createEncryptCipher($key)
        );
    }

    private static $instance;
    private $cipherFactory;
}
