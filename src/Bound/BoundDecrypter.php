<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Bound;

use Eloquent\Lockbox\Cipher\Parameters\CipherParametersInterface;
use Eloquent\Lockbox\Decrypter;
use Eloquent\Lockbox\DecrypterInterface;

/**
 * Binds a set of parameters to a decrypter.
 */
class BoundDecrypter extends AbstractBoundDecrypter
{
    /**
     * Construct a new bound decrypter.
     *
     * @param CipherParametersInterface $parameters The parameters to use.
     * @param DecrypterInterface|null   $decrypter  The decrypter to use.
     */
    public function __construct(
        CipherParametersInterface $parameters,
        DecrypterInterface $decrypter = null
    ) {
        if (null === $decrypter) {
            $decrypter = Decrypter::instance();
        }

        parent::__construct($parameters, $decrypter);
    }
}
