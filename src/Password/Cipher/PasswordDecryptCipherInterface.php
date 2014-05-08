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
 * The interface implemented by decrypt ciphers that use passwords.
 */
interface PasswordDecryptCipherInterface extends CipherInterface
{
    /**
     * Initialize this cipher.
     *
     * @param string $password The password to decrypt with.
     *
     * @throws InvalidKeyExceptionInterface If the supplied arguments are invalid.
     */
    public function initialize($password);
}
