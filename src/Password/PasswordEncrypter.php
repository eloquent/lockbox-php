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

use Eloquent\Confetti\CompoundTransform;
use Eloquent\Confetti\TransformInterface;
use Eloquent\Confetti\TransformStream;
use Eloquent\Confetti\TransformStreamInterface;
use Eloquent\Endec\Base64\Base64UrlEncodeTransform;
use Eloquent\Lockbox\Transform\Factory\PasswordEncryptTransformFactory;
use Eloquent\Lockbox\Transform\Factory\PasswordEncryptTransformFactoryInterface;

/**
 * Encrypts data and produces encoded output using passwords.
 */
class PasswordEncrypter implements PasswordEncrypterInterface
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
     * Construct a new encrypter.
     *
     * @param PasswordEncryptTransformFactoryInterface|null $transformFactory The transform factory to use.
     * @param TransformInterface|null                       $encodeTransform  The encode transform to use.
     */
    public function __construct(
        PasswordEncryptTransformFactoryInterface $transformFactory = null,
        TransformInterface $encodeTransform = null
    ) {
        if (null === $transformFactory) {
            $transformFactory = PasswordEncryptTransformFactory::instance();
        }
        if (null === $encodeTransform) {
            $encodeTransform = Base64UrlEncodeTransform::instance();
        }

        $this->transformFactory = $transformFactory;
        $this->encodeTransform = $encodeTransform;
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
     * Get the encode transform.
     *
     * @return TransformInterface The encode transform.
     */
    public function encodeTransform()
    {
        return $this->encodeTransform;
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

        $context = null;
        list($data) = $this->encodeTransform()
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
            new CompoundTransform(
                array(
                    $this->transformFactory()
                        ->createTransform($password, $iterations),
                    $this->encodeTransform(),
                )
            )
        );
    }

    private static $instance;
    private $transformFactory;
    private $encodeTransform;
}
