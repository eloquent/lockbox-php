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

use Eloquent\Lockbox\Cipher\Factory\CipherFactoryInterface;
use Eloquent\Lockbox\Cipher\Factory\EncryptCipherFactory;

/**
 * Encrypts data and produces raw output using keys.
 */
class RawEncrypter extends AbstractRawEncrypter
{
    /**
     * Get the static instance of this encrypter.
     *
     * @return EncrypterInterface The static encrypter.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new raw encrypter.
     *
     * @param CipherFactoryInterface|null $cipherFactory The cipher factory to use.
     */
    public function __construct(CipherFactoryInterface $cipherFactory = null)
    {
        if (null === $cipherFactory) {
            $cipherFactory = EncryptCipherFactory::instance();
        }

        parent::__construct($cipherFactory);
    }

    private static $instance;
}
