<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Password\Cipher\Factory;

use Eloquent\Lockbox\Cipher\CipherInterface;
use Eloquent\Lockbox\Cipher\Factory\CipherFactoryInterface;
use Eloquent\Lockbox\Key\KeyDeriver;
use Eloquent\Lockbox\Key\KeyDeriverInterface;
use Eloquent\Lockbox\Padding\PkcsPadding;
use Eloquent\Lockbox\Password\Cipher\PasswordDecryptCipher;

/**
 * Creates decrypt ciphers that use passwords.
 */
class PasswordDecryptCipherFactory implements CipherFactoryInterface
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
     * Construct a new password decrypt cipher factory.
     *
     * @param KeyDeriverInterface|null $keyDeriver The key deriver to use.
     * @param UnpadderInterface|null   $unpadder   The unpadder to use.
     */
    public function __construct(
        KeyDeriverInterface $keyDeriver = null,
        UnpadderInterface $unpadder = null
    ) {
        if (null === $keyDeriver) {
            $keyDeriver = KeyDeriver::instance();
        }
        if (null === $unpadder) {
            $unpadder = PkcsPadding::instance();
        }

        $this->keyDeriver = $keyDeriver;
        $this->unpadder = $unpadder;
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
        return new PasswordDecryptCipher(
            $this->keyDeriver(),
            $this->unpadder()
        );
    }

    private static $instance;
    private $keyDeriver;
    private $unpadder;
}
