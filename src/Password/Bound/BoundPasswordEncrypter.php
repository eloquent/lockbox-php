<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Password\Bound;

use Eloquent\Lockbox\Bound\AbstractBoundEncrypter;
use Eloquent\Lockbox\Cipher\Parameters\CipherParametersInterface;
use Eloquent\Lockbox\EncrypterInterface;
use Eloquent\Lockbox\Password\PasswordEncrypter;

/**
 * Binds a set of parameters to a password encrypter.
 */
class BoundPasswordEncrypter extends AbstractBoundEncrypter
{
    /**
     * Construct a new bound password encrypter.
     *
     * @param CipherParametersInterface $parameters The parameters to use.
     * @param EncrypterInterface|null   $encrypter  The encrypter to use.
     */
    public function __construct(
        CipherParametersInterface $parameters,
        EncrypterInterface $encrypter = null
    ) {
        if (null === $encrypter) {
            $encrypter = PasswordEncrypter::instance();
        }

        parent::__construct($parameters, $encrypter);
    }
}
