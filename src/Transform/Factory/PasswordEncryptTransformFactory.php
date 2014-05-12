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
use Eloquent\Lockbox\Padding\PadderInterface;
use Eloquent\Lockbox\Padding\PkcsPadding;
use Eloquent\Lockbox\Password\Cipher\PasswordEncryptCipher;
use Eloquent\Lockbox\Random\DevUrandom;
use Eloquent\Lockbox\Random\RandomSourceInterface;
use Eloquent\Lockbox\Transform\CipherTransform;
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
     * @param KeyDeriverInterface|null   $keyDeriver   The key deriver to use.
     * @param RandomSourceInterface|null $randomSource The random source to use.
     * @param PadderInterface|null       $padder       The padder to use.
     */
    public function __construct(
        KeyDeriverInterface $keyDeriver = null,
        RandomSourceInterface $randomSource = null,
        PadderInterface $padder = null
    ) {
        if (null === $keyDeriver) {
            $keyDeriver = KeyDeriver::instance();
        }
        if (null === $randomSource) {
            $randomSource = DevUrandom::instance();
        }
        if (null === $padder) {
            $padder = PkcsPadding::instance();
        }

        $this->keyDeriver = $keyDeriver;
        $this->randomSource = $randomSource;
        $this->padder = $padder;
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
     * Get the random source.
     *
     * @return RandomSourceInterface The random source.
     */
    public function randomSource()
    {
        return $this->randomSource;
    }

    /**
     * Get the padder.
     *
     * @return PadderInterface The padder.
     */
    public function padder()
    {
        return $this->padder;
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
        $cipher = new PasswordEncryptCipher(
            $this->keyDeriver(),
            $this->randomSource(),
            $this->padder()
        );
        $cipher->initialize($password, $iterations);

        return new CipherTransform($cipher);
    }

    private static $instance;
    private $keyDeriver;
    private $randomSource;
    private $padder;
}
