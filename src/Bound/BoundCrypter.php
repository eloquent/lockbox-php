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
use Eloquent\Lockbox\Crypter;
use Eloquent\Lockbox\CrypterInterface;

/**
 * Binds a set of parameters to a crypter.
 */
class BoundCrypter extends AbstractBoundCrypter
{
    /**
     * Construct a new bound crypter.
     *
     * @param CipherParametersInterface $encryptParameters The parameters to use when encrypting.
     * @param CipherParametersInterface $decryptParameters The parameters to use when decrypting.
     * @param CrypterInterface|null     $crypter           The crypter to use.
     */
    public function __construct(
        CipherParametersInterface $encryptParameters,
        CipherParametersInterface $decryptParameters,
        CrypterInterface $crypter = null
    ) {
        if (null === $crypter) {
            $crypter = Crypter::instance();
        }

        parent::__construct($encryptParameters, $decryptParameters, $crypter);
    }
}
