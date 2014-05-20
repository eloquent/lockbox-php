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

use Eloquent\Lockbox\AbstractRawDecrypter;
use Eloquent\Lockbox\Cipher\Factory\CipherFactoryInterface;
use Eloquent\Lockbox\DecrypterInterface;
use Eloquent\Lockbox\Password\Cipher\Factory\PasswordDecryptCipherFactory;

/**
 * Decrypts raw data using passwords.
 */
class RawPasswordDecrypter extends AbstractRawDecrypter
{
    /**
     * Get the static instance of this decrypter.
     *
     * @return DecrypterInterface The static decrypter.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new raw password decrypter.
     *
     * @param CipherFactoryInterface|null $cipherFactory The cipher factory to use.
     */
    public function __construct(CipherFactoryInterface $cipherFactory = null)
    {
        if (null === $cipherFactory) {
            $cipherFactory = PasswordDecryptCipherFactory::instance();
        }

        parent::__construct($cipherFactory);
    }

    private static $instance;
}
