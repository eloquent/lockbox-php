<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Password\Cipher\Parameters;

use Eloquent\Lockbox\Password\Password;
use Eloquent\Lockbox\Password\PasswordInterface;

/**
 * Cipher parameters for encrypting data with a password.
 */
class PasswordEncryptParameters implements PasswordEncryptParametersInterface
{
    /**
     * Construct a new encrypt parameters instance.
     *
     * @param PasswordInterface|string $password   The password to use.
     * @param integer                  $iterations The number of hash iterations to use.
     * @param string|null              $salt       The salt to use for key derivation, or null to generate one.
     * @param string|null              $iv         The initialization vector to use, or null to generate one.
     */
    public function __construct(
        $password,
        $iterations,
        $salt = null,
        $iv = null
    ) {
        $this->password = Password::adapt($password);
        $this->iterations = $iterations;
        $this->salt = $salt;
        $this->iv = $iv;
    }

    /**
     * Get the password.
     *
     * @return PasswordInterface The password.
     */
    public function password()
    {
        return $this->password;
    }

    /**
     * Get the number of hash iterations.
     *
     * @return integer The number of hash iterations.
     */
    public function iterations()
    {
        return $this->iterations;
    }

    /**
     * Get the salt to use for key derivation.
     *
     * @return string|null The salt to use for key derivation, or null if none was specified.
     */
    public function salt()
    {
        return $this->salt;
    }

    /**
     * Get the initialization vector.
     *
     * @return string|null The initialization vector, or null if none was specified.
     */
    public function iv()
    {
        return $this->iv;
    }

    /**
     * Erase these parameters, removing any sensitive data.
     */
    public function erase()
    {
        $this->password()->erase();

        unset($this->salt);
        unset($this->iv);
        $this->salt = $this->iv = null;
        $this->iterations = 1;
    }

    private $password;
    private $iterations;
    private $salt;
    private $iv;
}
