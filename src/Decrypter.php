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

use Eloquent\Endec\DecoderInterface;
use Eloquent\Lockbox\Cipher\Factory\CipherFactoryInterface;
use Eloquent\Lockbox\Cipher\Factory\DecryptCipherFactory;
use Eloquent\Lockbox\Cipher\Result\CipherResult;
use Eloquent\Lockbox\Cipher\Result\CipherResultInterface;
use Eloquent\Lockbox\Cipher\Result\CipherResultType;

/**
 * Decrypts encoded data using keys.
 */
class Decrypter extends AbstractDecrypter
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
     * Construct a new decrypter.
     *
     * @param CipherFactoryInterface|null $cipherFactory The cipher factory to use.
     * @param DecoderInterface|null       $decoder       The decoder to use.
     */
    public function __construct(
        CipherFactoryInterface $cipherFactory = null,
        DecoderInterface $decoder = null
    ) {
        if (null === $cipherFactory) {
            $cipherFactory = DecryptCipherFactory::instance();
        }

        parent::__construct($cipherFactory, $decoder);
    }

    /**
     * Create a new cipher result of the supplied type.
     *
     * @param CipherResultType $type The result type.
     *
     * @return CipherResultInterface The newly created cipher result.
     */
    protected function createResult(CipherResultType $type)
    {
        return new CipherResult($type);
    }

    private static $instance;
}
