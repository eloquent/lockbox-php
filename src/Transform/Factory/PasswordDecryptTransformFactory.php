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
use Eloquent\Lockbox\Key\KeyDeriverInterface;
use Eloquent\Lockbox\Padding\PkcsPadding;
use Eloquent\Lockbox\Padding\UnpadderInterface;
use Eloquent\Lockbox\Password\Cipher\PasswordDecryptCipher;
use Eloquent\Lockbox\Transform\CipherTransform;

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
     * Create a new transform for the supplied password.
     *
     * @param string $password The password to use.
     *
     * @return TransformInterface The newly created transform.
     */
    public function createTransform($password)
    {
        $cipher = new PasswordDecryptCipher(
            $this->keyDeriver(),
            $this->unpadder()
        );
        $cipher->initialize($password);

        return new CipherTransform($cipher);
    }

    private static $instance;
    private $keyDeriver;
    private $unpadder;
}
