<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Transform\Factory;

use Eloquent\Confetti\TransformInterface;
use Eloquent\Lockbox\Key\KeyDeriver;
use Eloquent\Lockbox\Password\Cipher\Factory\PasswordDecryptCipherFactory;
use Eloquent\Lockbox\Password\Cipher\Factory\PasswordDecryptCipherFactoryInterface;
use Eloquent\Lockbox\Transform\PasswordDecryptTransform;

/**
 * Creates decrypt transforms that use passwords.
 */
class PasswordDecryptTransformFactory implements
    PasswordDecryptTransformFactoryInterface
{
    /**
     * Get the static instance of this factory.
     *
     * @return PasswordDecryptTransformFactoryInterface The static factory.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new password decrypt transform factory.
     *
     * @param PasswordDecryptCipherFactoryInterface|null $cipherFactory The cipher factory to use.
     */
    public function __construct(
        PasswordDecryptCipherFactoryInterface $cipherFactory = null
    ) {
        if (null === $cipherFactory) {
            $cipherFactory = PasswordDecryptCipherFactory::instance();
        }

        $this->cipherFactory = $cipherFactory;
    }

    /**
     * Get the cipher factory.
     *
     * @return PasswordDecryptCipherFactoryInterface The cipher factory.
     */
    public function cipherFactory()
    {
        return $this->cipherFactory;
    }

    /**
     * Create a new transform for the supplied password.
     *
     * @param string $password The password to use.
     *
     * @return TransformInterface The newly created transform.
     */
    public function createTransform($password)
    {
        return new PasswordDecryptTransform(
            $this->cipherFactory()->createPasswordDecryptCipher($password)
        );
    }

    private static $instance;
    private $cipherFactory;
    private $keyDeriver;
}
