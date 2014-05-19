<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Cipher;

use Eloquent\Lockbox\Cipher\Exception\UnsupportedCipherParametersException;
use Eloquent\Lockbox\Cipher\Parameters\CipherParametersInterface;
use Eloquent\Lockbox\Cipher\Parameters\EncryptParametersInterface;
use Eloquent\Lockbox\Key\KeyInterface;

/**
 * Encrypts data with a key.
 */
class EncryptCipher extends AbstractEncryptCipher
{
    /**
     * Initialize this cipher.
     *
     * @param CipherParametersInterface $parameters The parameters to use.
     *
     * @throws UnsupportedCipherParametersException If unsupported parameters are supplied.
     */
    public function initialize(CipherParametersInterface $parameters)
    {
        if ($parameters instanceof EncryptParametersInterface) {
            $this->doInitialize($parameters->key(), $parameters->iv());
        } elseif ($parameters instanceof KeyInterface) {
            $this->doInitialize($parameters);
        } else {
            throw new UnsupportedCipherParametersException($this, $parameters);
        }
    }

    /**
     * Get the encryption header.
     *
     * @param string $iv The initialization vector.
     *
     * @return string The header.
     */
    protected function header($iv)
    {
        return chr(1) . chr(1) . $iv;
    }
}
