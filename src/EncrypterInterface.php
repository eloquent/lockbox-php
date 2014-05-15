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
use Eloquent\Lockbox\Stream\CipherStreamInterface;

/**
 * The interface implemented by encrypters.
 */
interface EncrypterInterface
{
    /**
     * Encrypt a data packet.
     *
     * @param CipherParametersInterface $parameters The parameters to encrypt with.
     * @param string                    $data       The data to encrypt.
     *
     * @return string The encrypted data.
     */
    public function encrypt(CipherParametersInterface $parameters, $data);

    /**
     * Create a new encrypt stream.
     *
     * @param CipherParametersInterface $parameters The parameters to encrypt with.
     *
     * @return CipherStreamInterface The newly created encrypt stream.
     */
    public function createEncryptStream(CipherParametersInterface $parameters);
}
