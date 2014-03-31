<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Password;

use Eloquent\Confetti\TransformStreamInterface;

/**
 * The interface implemented by password encrypters.
 */
interface PasswordEncrypterInterface
{
    /**
     * Encrypt a data packet.
     *
     * @param string  $password   The password to encrypt with.
     * @param integer $iterations The number of hash iterations to use.
     * @param string  $data       The data to encrypt.
     *
     * @return string The encrypted data.
     */
    public function encrypt($password, $iterations, $data);

    /**
     * Create a new encrypt stream.
     *
     * @param string  $password   The password to encrypt with.
     * @param integer $iterations The number of hash iterations to use.
     *
     * @return TransformStreamInterface The newly created encrypt stream.
     */
    public function createEncryptStream($password, $iterations);
}
