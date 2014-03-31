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
 * An abstract base class for implementing password ciphers.
 */
abstract class AbstractPasswordCipher implements PasswordCipherInterface
{
    /**
     * Construct a new password cipher.
     *
     * @param PasswordEncrypterInterface $encrypter The encrypter to use.
     * @param PasswordDecrypterInterface $decrypter The decrypter to use.
     */
    public function __construct(
        PasswordEncrypterInterface $encrypter,
        PasswordDecrypterInterface $decrypter
    ) {
        $this->encrypter = $encrypter;
        $this->decrypter = $decrypter;
    }

    /**
     * Get the encrypter.
     *
     * @return PasswordEncrypterInterface The encrypter.
     */
    public function encrypter()
    {
        return $this->encrypter;
    }

    /**
     * Get the decrypter.
     *
     * @return PasswordDecrypterInterface The decrypter.
     */
    public function decrypter()
    {
        return $this->decrypter;
    }
    /**
     * Encrypt a data packet.
     *
     * @param string  $password   The password to encrypt with.
     * @param integer $iterations The number of hash iterations to use.
     * @param string  $data       The data to encrypt.
     *
     * @return string The encrypted data.
     */
    public function encrypt($password, $iterations, $data)
    {
        return $this->encrypter()->encrypt($password, $iterations, $data);
    }

    /**
     * Decrypt a data packet.
     *
     * @param string $password The password to decrypt with.
     * @param string $data     The data to decrypt.
     *
     * @return tuple<string,integer>             A 2-tuple of the decrypted data, and the number of iterations used.
     * @throws PasswordDecryptionFailedException If the decryption failed.
     */
    public function decrypt($password, $data)
    {
        return $this->decrypter()->decrypt($password, $data);
    }

    /**
     * Create a new encrypt stream.
     *
     * @param string  $password   The password to encrypt with.
     * @param integer $iterations The number of hash iterations to use.
     *
     * @return TransformStreamInterface The newly created encrypt stream.
     */
    public function createEncryptStream($password, $iterations)
    {
        return $this->encrypter()->createEncryptStream($password, $iterations);
    }

    /**
     * Create a new decrypt stream.
     *
     * @param string $password The password to decrypt with.
     *
     * @return TransformStreamInterface The newly created decrypt stream.
     */
    public function createDecryptStream($password)
    {
        return $this->decrypter()->createDecryptStream($password);
    }

    private $encrypter;
    private $decrypter;
}