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
 * Encrypts and decrypts encoded data using keys.
 */
class Crypter extends AbstractCrypter
{
    /**
     * Get the static instance of this crypter.
     *
     * @return CrypterInterface The static crypter.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new crypter.
     *
     * @param EncrypterInterface|null $encrypter The encrypter to use.
     * @param DecrypterInterface|null $decrypter The decrypter to use.
     */
    public function __construct(
        EncrypterInterface $encrypter = null,
        DecrypterInterface $decrypter = null
    ) {
        if (null === $encrypter) {
            $encrypter = Encrypter::instance();
        }
        if (null === $decrypter) {
            $decrypter = Decrypter::instance();
        }

        parent::__construct($encrypter, $decrypter);
    }

    private static $instance;
}
