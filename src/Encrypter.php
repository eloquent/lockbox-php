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
     * @param EncrypterInterface|null $rawEncrypter The raw encrypter to use.
     * @param EncoderInterface|null   $encoder      The encoder to use.
     */
    public function __construct(
        EncrypterInterface $rawEncrypter = null,
        EncoderInterface $encoder = null
    ) {
        if (null === $rawEncrypter) {
            $rawEncrypter = RawEncrypter::instance();
        }

        parent::__construct($rawEncrypter, $encoder);
    }

    private static $instance;
}
