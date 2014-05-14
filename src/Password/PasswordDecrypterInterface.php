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

use Eloquent\Lockbox\Password\Cipher\Result\PasswordDecryptionResultInterface;
use Eloquent\Lockbox\Stream\CipherStreamInterface;

/**
 * The interface implemented by password decrypters.
 */
interface PasswordDecrypterInterface
{
    /**
     * Decrypt a data packet.
     *
     * @param string $password The password to decrypt with.
     * @param string $data     The data to decrypt.
     *
     * @return PasswordDecryptionResultInterface The decryption result.
     */
    public function decrypt($password, $data);

    /**
     * Create a new decrypt stream.
     *
     * @param string $password The password to decrypt with.
     *
     * @return CipherStreamInterface The newly created decrypt stream.
     */
    public function createDecryptStream($password);
}
