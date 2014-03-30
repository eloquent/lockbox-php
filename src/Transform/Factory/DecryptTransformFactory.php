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
use Eloquent\Lockbox\Key\KeyInterface;
use Eloquent\Lockbox\Transform\DecryptTransform;

/**
 * Creates decrypt transforms that use keys.
 */
class DecryptTransformFactory implements KeyTransformFactoryInterface
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
     * Create a new transform for the supplied key.
     *
     * @param KeyInterface $key The key to use.
     *
     * @return TransformInterface The newly created transform.
     */
    public function createTransform(KeyInterface $key)
    {
        return new DecryptTransform($key);
    }

    private static $instance;
}
