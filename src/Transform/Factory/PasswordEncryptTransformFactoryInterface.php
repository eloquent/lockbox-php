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

/**
 * The interface implemented by encrypt transform factories that use passwords.
 */
interface PasswordEncryptTransformFactoryInterface
{
    /**
     * Create a new transform for the supplied password.
     *
     * @param string  $password   The password to use.
     * @param integer $iterations The number of hash iterations to use.
     *
     * @return TransformInterface The newly created transform.
     */
    public function createTransform($password, $iterations);
}
