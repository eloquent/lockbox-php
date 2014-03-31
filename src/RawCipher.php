<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox;

/**
 * Encrypts and decrypts raw data using keys.
 */
class RawCipher extends AbstractCipher
{
    /**
     * Get the static instance of this cipher.
     *
     * @return CipherInterface The static cipher.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new cipher.
     *
     * @param EncrypterInterface|null $encrypter The encrypter to use.
     * @param DecrypterInterface|null $decrypter The decrypter to use.
     */
    public function __construct(
        EncrypterInterface $encrypter = null,
        DecrypterInterface $decrypter = null
    ) {
        if (null === $encrypter) {
            $encrypter = RawEncrypter::instance();
        }
        if (null === $decrypter) {
            $decrypter = RawDecrypter::instance();
        }

        parent::__construct($encrypter, $decrypter);
    }

    private static $instance;
}
