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

use Eloquent\Lockbox\BoundEncrypterInterface;

/**
 * Binds a password to an encrypter.
 */
class BoundPasswordEncrypter implements BoundEncrypterInterface
{
    /**
     * Construct a new bound password encrypter.
     *
     * @param string                          $password   The password to encrypt with.
     * @param integer                         $iterations The number of hash iterations to use.
     * @param PasswordEncrypterInterface|null $encrypter  The encrypter to use.
     */
    public function __construct(
        $password,
        $iterations,
        PasswordEncrypterInterface $encrypter = null
    ) {
        if (null === $encrypter) {
            $encrypter = Encrypter::instance();
        }

        $this->password = $password;
        $this->iterations = $iterations;
        $this->encrypter = $encrypter;
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
     * Get the encrypter.
     *
     * @return PasswordEncrypterInterface The encrypter;
     */
    public function encrypter()
    {
        return $this->encrypter;
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
        return $this->encrypter()
            ->encrypt($this->password(), $this->iterations(), $data);
    }

    private $password;
    private $iterations;
    private $encrypter;
}
