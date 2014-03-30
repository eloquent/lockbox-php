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

use Eloquent\Endec\Transform\DataTransformInterface;
use Eloquent\Lockbox\Key\KeyDeriver;
use Eloquent\Lockbox\Key\KeyDeriverInterface;
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
     * Create a new transform for the supplied password.
     *
     * @param string $password The password to use.
     *
     * @return DataTransformInterface The newly created transform.
     */
    public function createTransform($password)
    {
        return new PasswordDecryptTransform($password, $this->keyDeriver());
    }

    private static $instance;
    private $keyDeriver;
    private $randomSource;
}
