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
 * The interface implemented by password decrypt cipher factories.
 */
interface PasswordDecryptCipherFactoryInterface
{
    /**
     * Create a new password decrypt cipher.
     *
     * @param string $password The password to decrypt with.
     *
     * @return CipherInterface The newly created cipher.
     */
    public function createPasswordDecryptCipher($password);
}
