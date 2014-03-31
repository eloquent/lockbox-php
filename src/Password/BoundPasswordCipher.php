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
use Eloquent\Lockbox\BoundCipherInterface;

/**
 * Binds a password to a cipher.
 */
class BoundPasswordCipher implements BoundCipherInterface
{
    /**
     * Construct a new bound password cipher.
     *
     * @param string                       $password   The password to use.
     * @param integer                      $iterations The number of hash iterations to use.
     * @param PasswordCipherInterface|null $cipher     The cipher to use.
     */
    public function __construct(
        $password,
        $iterations,
        PasswordCipherInterface $cipher = null
    ) {
        if (null === $cipher) {
            $cipher = PasswordCipher::instance();
        }

        $this->password = $password;
        $this->iterations = $iterations;
        $this->cipher = $cipher;
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
     * Get the cipher.
     *
     * @return PasswordCipherInterface The cipher.
     */
    public function cipher()
    {
        return $this->cipher;
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
        return $this->cipher()
            ->encrypt($this->password(), $this->iterations(), $data);
    }

    /**
     * Decrypt a data packet.
     *
     * @param string $data The data to decrypt.
     *
     * @return string                              The decrypted data.
     * @throws Exception\DecryptionFailedException If the decryption failed.
     */
    public function decrypt($data)
    {
        return $this->cipher()->decrypt($this->password(), $data);
    }

    /**
     * Create a new encrypt stream.
     *
     * @return TransformStreamInterface The newly created encrypt stream.
     */
    public function createEncryptStream()
    {
        return $this->cipher()
            ->createEncryptStream($this->password(), $this->iterations());
    }

    /**
     * Create a new decrypt stream.
     *
     * @return TransformStreamInterface The newly created decrypt stream.
     */
    public function createDecryptStream()
    {
        return $this->cipher()->createDecryptStream($this->password());
    }

    private $password;
    private $iterations;
    private $cipher;
}
