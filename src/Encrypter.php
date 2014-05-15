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

use Eloquent\Endec\EncoderInterface;
use Eloquent\Lockbox\Cipher\Factory\CipherFactoryInterface;
use Eloquent\Lockbox\Cipher\Factory\EncryptCipherFactory;

/**
 * Encrypts data and produces encoded output using keys.
 */
class Encrypter extends AbstractEncrypter
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
     * Construct a new encrypter.
     *
     * @param CipherFactoryInterface|null $cipherFactory The cipher factory to use.
     * @param EncoderInterface|null       $encoder       The encoder to use.
     */
    public function __construct(
        CipherFactoryInterface $cipherFactory = null,
        EncoderInterface $encoder = null
    ) {
        if (null === $cipherFactory) {
            $cipherFactory = EncryptCipherFactory::instance();
        }

        parent::__construct($cipherFactory, $encoder);
    }

    private static $instance;
}
