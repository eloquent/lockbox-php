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

use Eloquent\Lockbox\Cipher\AbstractEncryptCipher;
use Eloquent\Lockbox\Key\KeyDeriver;
use Eloquent\Lockbox\Key\KeyDeriverInterface;
use Eloquent\Lockbox\Padding\PadderInterface;

/**
 * Encrypts data with a password.
 */
class PasswordEncryptCipher extends AbstractEncryptCipher
{
    /**
     * Construct a new password encrypt data transform.
     *
     * @param string                   $password   The password to encrypt with.
     * @param integer                  $iterations The number of hash iterations to use.
     * @param string                   $salt       The salt to use for key derivation.
     * @param string                   $iv         The initialization vector to use.
     * @param KeyDeriverInterface|null $keyDeriver The key deriver to use.
     * @param PadderInterface|null     $padder     The padder to use.
     */
    public function __construct(
        $password,
        $iterations,
        $salt,
        $iv,
        KeyDeriverInterface $keyDeriver = null,
        PadderInterface $padder = null
    ) {
        if (null === $keyDeriver) {
            $keyDeriver = KeyDeriver::instance();
        }

        parent::__construct($iv, $padder);

        $this->password = $password;
        $this->iterations = $iterations;
        $this->salt = $salt;
        $this->keyDeriver = $keyDeriver;
    }

    /**
     * Get the key deriver.
     *
     * @return KeyDeriverInterface The key deriver.
     */
    public function keyDeriver()
    {
        return $this->keyDeriver;
    }

    /**
     * Produce the key to use.
     *
     * @return KeyInterface The key.
     */
    protected function produceKey()
    {
        list($key) = $this->keyDeriver()->deriveKeyFromPassword(
            $this->password,
            $this->iterations,
            $this->salt
        );

        return $key;
    }

    /**
     * Get the encryption header.
     *
     * @param string $iv The initialization vector.
     *
     * @return string The header.
     */
    protected function header($iv)
    {
        return chr(1) . chr(2) . pack('N', $this->iterations) . $this->salt .
            $iv;
    }

    private $password;
    private $iterations;
    private $salt;
    private $keyDeriver;
}
