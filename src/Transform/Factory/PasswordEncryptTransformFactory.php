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
use Eloquent\Lockbox\Password\Cipher\Factory\PasswordEncryptCipherFactory;
use Eloquent\Lockbox\Password\Cipher\Factory\PasswordEncryptCipherFactoryInterface;
use Eloquent\Lockbox\Transform\PasswordEncryptTransform;

/**
 * Creates encrypt transforms that use passwords.
 */
class PasswordEncryptTransformFactory implements
    PasswordEncryptTransformFactoryInterface
{
    /**
     * Get the static instance of this factory.
     *
     * @return PasswordEncryptTransformFactoryInterface The static factory.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new password encrypt transform factory.
     *
     * @param PasswordEncryptCipherFactoryInterface|null $cipherFactory The cipher factory to use.
     */
    public function __construct(
        PasswordEncryptCipherFactoryInterface $cipherFactory = null
    ) {
        if (null === $cipherFactory) {
            $cipherFactory = PasswordEncryptCipherFactory::instance();
        }

        $this->cipherFactory = $cipherFactory;
    }

    /**
     * Get the cipher factory.
     *
     * @return PasswordEncryptCipherFactoryInterface The cipher factory.
     */
    public function cipherFactory()
    {
        return $this->cipherFactory;
    }

    /**
     * Create a new transform for the supplied password.
     *
     * @param string  $password   The password to use.
     * @param integer $iterations The number of hash iterations to use.
     *
     * @return TransformInterface The newly created transform.
     */
    public function createTransform($password, $iterations)
    {
        return new PasswordEncryptTransform(
            $this->cipherFactory()
                ->createPasswordEncryptCipher($password, $iterations)
        );
    }

    private static $instance;
    private $cipherFactory;
}
