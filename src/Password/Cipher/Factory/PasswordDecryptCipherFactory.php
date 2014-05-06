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

use Eloquent\Lockbox\Key\KeyDeriver;
use Eloquent\Lockbox\Key\KeyDeriverInterface;
use Eloquent\Lockbox\Password\Cipher\PasswordDecryptCipher;

/**
 * Creates password decrypt ciphers.
 */
class PasswordDecryptCipherFactory implements
    PasswordDecryptCipherFactoryInterface
{
    /**
     * Get the static instance of this factory.
     *
     * @return PasswordDecryptCipherFactoryInterface The static factory.
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
     */
    public function __construct(KeyDeriverInterface $keyDeriver = null)
    {
        if (null === $keyDeriver) {
            $keyDeriver = KeyDeriver::instance();
        }

        $this->keyDeriver = $keyDeriver;
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
     * Create a new password decrypt cipher.
     *
     * @param string $password The password to decrypt with.
     *
     * @return CipherInterface The newly created cipher.
     */
    public function createPasswordDecryptCipher($password)
    {
        return new PasswordDecryptCipher($password, $this->keyDeriver());
    }

    private static $instance;
    private $keyDeriver;
}
