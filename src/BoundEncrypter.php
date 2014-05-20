<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox;

use Eloquent\Lockbox\Cipher\Parameters\CipherParametersInterface;

/**
 * Binds a set of parameters to an encrypter.
 */
class BoundEncrypter extends AbstractBoundEncrypter
{
    /**
     * Construct a new bound encrypter.
     *
     * @param CipherParametersInterface $parameters The parameters to use.
     * @param EncrypterInterface|null   $encrypter  The encrypter to use.
     */
    public function __construct(
        CipherParametersInterface $parameters,
        EncrypterInterface $encrypter = null
    ) {
        if (null === $encrypter) {
            $encrypter = Encrypter::instance();
        }

        parent::__construct($parameters, $encrypter);
    }
}
