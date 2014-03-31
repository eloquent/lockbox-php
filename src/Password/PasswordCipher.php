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

/**
 * Encrypts and decrypts encoded data using passwords.
 */
class PasswordCipher extends AbstractPasswordCipher
{
    /**
     * Get the static instance of this cipher.
     *
     * @return PasswordCipherInterface The static cipher.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new password cipher.
     *
     * @param PasswordEncrypterInterface|null $encrypter The encrypter to use.
     * @param PasswordDecrypterInterface|null $decrypter The decrypter to use.
     */
    public function __construct(
        PasswordEncrypterInterface $encrypter = null,
        PasswordDecrypterInterface $decrypter = null
    ) {
        if (null === $encrypter) {
            $encrypter = PasswordEncrypter::instance();
        }
        if (null === $decrypter) {
            $decrypter = PasswordDecrypter::instance();
        }

        parent::__construct($encrypter, $decrypter);
    }

    private static $instance;
}
