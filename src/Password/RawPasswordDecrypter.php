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
use Eloquent\Lockbox\Exception\PasswordDecryptionFailedException;
use Eloquent\Lockbox\Transform\Factory\PasswordDecryptTransformFactory;
use Eloquent\Lockbox\Transform\Factory\PasswordDecryptTransformFactoryInterface;

/**
 * Decrypts raw data using passwords.
 */
class RawPasswordDecrypter implements PasswordDecrypterInterface
{
    /**
     * Get the static instance of this decrypter.
     *
     * @return PasswordEncrypterInterface The static decrypter.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new raw password decrypter.
     *
     * @param PasswordDecryptTransformFactoryInterface|null $transformFactory The transform factory to use.
     */
    public function __construct(
        PasswordDecryptTransformFactoryInterface $transformFactory = null
    ) {
        if (null === $transformFactory) {
            $transformFactory = PasswordDecryptTransformFactory::instance();
        }

        $this->transformFactory = $transformFactory;
    }

    /**
     * Get the transform factory.
     *
     * @return PasswordDecryptTransformFactoryInterface The transform factory.
     */
    public function transformFactory()
    {
        return $this->transformFactory;
    }

    /**
     * Decrypt a data packet.
     *
     * @param string $password The password to decrypt with.
     * @param string $data     The data to decrypt.
     *
     * @return tuple<string,integer>             A 2-tuple of the decrypted data, and the number of iterations used.
     * @throws PasswordDecryptionFailedException If the decryption failed.
     */
    public function decrypt($password, $data)
    {
        list($data) = $this->transformFactory()
            ->createTransform($password)
            ->transform($data, $context, true);

        return $data;
    }

    /**
     * Create a new decrypt stream.
     *
     * @param string $password The password to decrypt with.
     *
     * @return TransformStreamInterface The newly created decrypt stream.
     */
    public function createDecryptStream($password)
    {
        return new TransformStream(
            $this->transformFactory()->createTransform($password)
        );
    }

    private static $instance;
    private $transformFactory;
}
