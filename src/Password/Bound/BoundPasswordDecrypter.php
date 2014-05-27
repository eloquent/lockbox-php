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

use Eloquent\Lockbox\Bound\AbstractBoundDecrypter;
use Eloquent\Lockbox\Cipher\Parameters\CipherParametersInterface;
use Eloquent\Lockbox\DecrypterInterface;
use Eloquent\Lockbox\Password\PasswordDecrypter;

/**
 * Binds a set of parameters to a password decrypter.
 */
class BoundPasswordDecrypter extends AbstractBoundDecrypter
{
    /**
     * Construct a new bound password decrypter.
     *
     * @param CipherParametersInterface $parameters The parameters to use.
     * @param DecrypterInterface|null   $decrypter  The decrypter to use.
     */
    public function __construct(
        CipherParametersInterface $parameters,
        DecrypterInterface $decrypter = null
    ) {
        if (null === $decrypter) {
            $decrypter = PasswordDecrypter::instance();
        }

        parent::__construct($parameters, $decrypter);
    }
}
