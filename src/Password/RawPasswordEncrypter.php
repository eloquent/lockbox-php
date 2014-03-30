<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Password;

use Eloquent\Endec\Transform\TransformStream;
use Eloquent\Endec\Transform\TransformStreamInterface;
use Eloquent\Lockbox\Transform\Factory\PasswordEncryptTransformFactory;
use Eloquent\Lockbox\Transform\Factory\PasswordEncryptTransformFactoryInterface;

/**
 * Encrypts data and produces raw output using passwords.
 */
class RawPasswordEncrypter implements PasswordEncrypterInterface
{
    /**
     * Get the static instance of this encrypter.
     *
     * @return PasswordEncrypterInterface The static encrypter.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new raw password encrypter.
     *
     * @param PasswordEncryptTransformFactoryInterface|null $transformFactory The transform factory to use.
     */
    public function __construct(
        PasswordEncryptTransformFactoryInterface $transformFactory = null
    ) {
        if (null === $transformFactory) {
            $transformFactory = PasswordEncryptTransformFactory::instance();
        }

        $this->transformFactory = $transformFactory;
    }

    /**
     * Get the transform factory.
     *
     * @return PasswordEncryptTransformFactoryInterface The transform factory.
     */
    public function transformFactory()
    {
        return $this->transformFactory;
    }

    /**
     * Encrypt a data packet.
     *
     * @param string  $password   The password to encrypt with.
     * @param integer $iterations The number of hash iterations to use.
     * @param string  $data       The data to encrypt.
     *
     * @return string The encrypted data.
     */
    public function encrypt($password, $iterations, $data)
    {
        list($data) = $this->transformFactory()
            ->createTransform($password, $iterations)
            ->transform($data, $context, true);

        return $data;
    }

    /**
     * Create a new encrypt stream.
     *
     * @param string  $password   The password to encrypt with.
     * @param integer $iterations The number of hash iterations to use.
     *
     * @return TransformStreamInterface The newly created encrypt stream.
     */
    public function createEncryptStream($password, $iterations)
    {
        return new TransformStream(
            $this->transformFactory()->createTransform($password, $iterations)
        );
    }

    private static $instance;
    private $transformFactory;
}
