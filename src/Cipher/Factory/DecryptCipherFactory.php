<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Cipher\Factory;

use Eloquent\Lockbox\Cipher\CipherInterface;
use Eloquent\Lockbox\Cipher\DecryptCipher;
use Eloquent\Lockbox\Padding\PkcsPadding;
use Eloquent\Lockbox\Padding\UnpadderInterface;

/**
 * Creates decrypt ciphers that use keys.
 */
class DecryptCipherFactory implements CipherFactoryInterface
{
    /**
     * Get the static instance of this factory.
     *
     * @return CipherFactoryInterface The static factory.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new decrypt cipher factory.
     *
     * @param UnpadderInterface|null $unpadder The unpadder to use.
     */
    public function __construct(UnpadderInterface $unpadder = null)
    {
        if (null === $unpadder) {
            $unpadder = PkcsPadding::instance();
        }

        $this->unpadder = $unpadder;
    }

    /**
     * Get the unpadder.
     *
     * @return UnpadderInterface The unpadder.
     */
    public function unpadder()
    {
        return $this->unpadder;
    }

    /**
     * Create a new cipher.
     *
     * @return CipherInterface The newly created cipher.
     */
    public function createCipher()
    {
        return new DecryptCipher($this->unpadder());
    }

    private static $instance;
    private $randomSource;
    private $unpadder;
}
