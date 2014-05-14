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

use Eloquent\Lockbox\BoundDecrypterInterface;
use Eloquent\Lockbox\Password\Cipher\Result\PasswordDecryptionResultInterface;
use Eloquent\Lockbox\Stream\CipherStreamInterface;

/**
 * Binds a password to a decrypter.
 */
class BoundPasswordDecrypter implements BoundDecrypterInterface
{
    /**
     * Construct a new bound decrypter.
     *
     * @param string                          $password  The password to decrypt with.
     * @param PasswordDecrypterInterface|null $decrypter The decrypter to use.
     */
    public function __construct(
        $password,
        PasswordDecrypterInterface $decrypter = null
    ) {
        if (null === $decrypter) {
            $decrypter = PasswordDecrypter::instance();
        }

        $this->password = $password;
        $this->decrypter = $decrypter;
    }

    /**
     * Get the password.
     *
     * @return string The password.
     */
    public function password()
    {
        return $this->password;
    }

    /**
     * Get the decrypter.
     *
     * @return PasswordDecrypterInterface The decrypter;
     */
    public function decrypter()
    {
        return $this->decrypter;
    }

    /**
     * Decrypt a data packet.
     *
     * @param string $data The data to decrypt.
     *
     * @return PasswordDecryptionResultInterface The decryption result.
     */
    public function decrypt($data)
    {
        return $this->decrypter()->decrypt($this->password(), $data);
    }

    /**
     * Create a new decrypt stream.
     *
     * @return CipherStreamInterface The newly created decrypt stream.
     */
    public function createDecryptStream()
    {
        return $this->decrypter()->createDecryptStream($this->password());
    }

    private $password;
    private $decrypter;
}
