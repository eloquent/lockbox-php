<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Password\Cipher\Factory;

use Eloquent\Lockbox\Cipher\CipherInterface;

/**
 * The interface implemented by password encrypt cipher factories.
 */
interface PasswordEncryptCipherFactoryInterface
{
    /**
     * Create a new password encrypt cipher.
     *
     * @param string      $password   The password to encrypt with.
     * @param integer     $iterations The number of hash iterations to use.
     * @param string|null $salt       The salt to use for key derivation, or null to generate one.
     * @param string|null $iv         The initialization vector to use, or null to generate one.
     *
     * @return CipherInterface The newly created cipher.
     */
    public function createPasswordEncryptCipher(
        $password,
        $iterations,
        $salt = null,
        $iv = null
    );
}
