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
use Eloquent\Endec\Base64\Base64UrlDecodeTransform;
use Eloquent\Endec\Exception\EncodingExceptionInterface;
use Eloquent\Lockbox\Exception\PasswordDecryptionFailedException;
use Eloquent\Lockbox\Transform\Factory\PasswordDecryptTransformFactory;
use Eloquent\Lockbox\Transform\Factory\PasswordDecryptTransformFactoryInterface;

/**
 * Decrypts encoded data using passwords.
 */
class PasswordDecrypter implements PasswordDecrypterInterface
{
    /**
     * Get the static instance of this decrypter.
     *
     * @return PasswordDecrypterInterface The static decrypter.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new decrypter.
     *
     * @param PasswordDecryptTransformFactoryInterface|null $transformFactory The transform factory to use.
     * @param TransformInterface|null                       $decodeTransform  The decode transform to use.
     */
    public function __construct(
        PasswordDecryptTransformFactoryInterface $transformFactory = null,
        TransformInterface $decodeTransform = null
    ) {
        if (null === $transformFactory) {
            $transformFactory = PasswordDecryptTransformFactory::instance();
        }
        if (null === $decodeTransform) {
            $decodeTransform = Base64UrlDecodeTransform::instance();
        }

        $this->transformFactory = $transformFactory;
        $this->decodeTransform = $decodeTransform;
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
     * Get the decode transform.
     *
     * @return TransformInterface The decode transform.
     */
    public function decodeTransform()
    {
        return $this->decodeTransform;
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
        try {
            list($data) = $this->decodeTransform()
                ->transform($data, $context, true);
        } catch (EncodingExceptionInterface $e) {
            throw new PasswordDecryptionFailedException($password, $e);
        }

        $transform = $this->transformFactory()->createTransform($password);
        $context = null;
        list($data) = $transform->transform($data, $context, true);

        return array($data, $transform->iterations());
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
            new CompoundTransform(
                array(
                    $this->decodeTransform(),
                    $this->transformFactory()->createTransform($password),
                )
            )
        );
    }

    private static $instance;
    private $transformFactory;
    private $decodeTransform;
}
