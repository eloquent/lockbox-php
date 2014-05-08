<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Password\Cipher;

use Eloquent\Lockbox\Cipher\CipherInterface;
use Eloquent\Lockbox\Key\Exception\InvalidKeyExceptionInterface;

/**
 * The interface implemented by encrypt ciphers that use passwords.
 */
interface PasswordEncryptCipherInterface extends CipherInterface
{
    /**
     * Initialize this cipher.
     *
     * @param string      $password   The password to encrypt with.
     * @param integer     $iterations The number of hash iterations to use.
     * @param string|null $salt       The salt to use for key derivation, or null to generate one.
     * @param string|null $iv         The initialization vector to use, or null to generate one.
     *
     * @throws InvalidKeyExceptionInterface If the supplied arguments are invalid.
     */
    public function initialize(
        $password,
        $iterations,
        $salt = null,
        $iv = null
    );
}
