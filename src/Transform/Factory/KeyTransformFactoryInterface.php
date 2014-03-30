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

/**
 * The interface implemented by cryptographic transform factories that use keys.
 */
interface KeyTransformFactoryInterface
{
    /**
     * Create a new transform for the supplied key.
     *
     * @param KeyInterface $key The key to use.
     *
     * @return DataTransformInterface The newly created transform.
     */
    public function createTransform(KeyInterface $key);
}
