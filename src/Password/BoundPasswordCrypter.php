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
use Eloquent\Lockbox\BoundCrypterInterface;
use Eloquent\Lockbox\Password\Cipher\Result\PasswordDecryptionResultInterface;

/**
 * Binds a password to a crypter.
 */
class BoundPasswordCrypter implements BoundCrypterInterface
{
    /**
     * Construct a new bound password crypter.
     *
     * @param string                        $password   The password to use.
     * @param integer                       $iterations The number of hash iterations to use.
     * @param PasswordCrypterInterface|null $crypter    The crypter to use.
     */
    public function __construct(
        $password,
        $iterations,
        PasswordCrypterInterface $crypter = null
    ) {
        if (null === $crypter) {
            $crypter = PasswordCrypter::instance();
        }

        $this->password = $password;
        $this->iterations = $iterations;
        $this->crypter = $crypter;
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
     * Get the number of hash iterations.
     *
     * @return integer The hash iterations.
     */
    public function iterations()
    {
        return $this->iterations;
    }

    /**
     * Get the crypter.
     *
     * @return PasswordCrypterInterface The crypter.
     */
    public function crypter()
    {
        return $this->crypter;
    }

    /**
     * Encrypt a data packet.
     *
     * @param string $data The data to encrypt.
     *
     * @return string The encrypted data.
     */
    public function encrypt($data)
    {
        return $this->crypter()
            ->encrypt($this->password(), $this->iterations(), $data);
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
        return $this->crypter()->decrypt($this->password(), $data);
    }

    /**
     * Create a new encrypt stream.
     *
     * @return TransformStreamInterface The newly created encrypt stream.
     */
    public function createEncryptStream()
    {
        return $this->crypter()
            ->createEncryptStream($this->password(), $this->iterations());
    }

    /**
     * Create a new decrypt stream.
     *
     * @return TransformStreamInterface The newly created decrypt stream.
     */
    public function createDecryptStream()
    {
        return $this->crypter()->createDecryptStream($this->password());
    }

    private $password;
    private $iterations;
    private $crypter;
}
