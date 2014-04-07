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
use Eloquent\Confetti\TransformStreamInterface;
use Eloquent\Endec\Base64\Base64UrlDecodeTransform;
use Eloquent\Lockbox\Result\DecryptionResultType;
use Eloquent\Lockbox\Result\PasswordDecryptionResult;
use Eloquent\Lockbox\Result\PasswordDecryptionResultInterface;
use Eloquent\Lockbox\Stream\DecryptStream;
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
     * @param PasswordDecrypterInterface|null               $rawDecrypter     The raw decrypter to use.
     * @param PasswordDecryptTransformFactoryInterface|null $transformFactory The transform factory to use.
     * @param TransformInterface|null                       $decodeTransform  The decode transform to use.
     */
    public function __construct(
        PasswordDecrypterInterface $rawDecrypter = null,
        PasswordDecryptTransformFactoryInterface $transformFactory = null,
        TransformInterface $decodeTransform = null
    ) {
        if (null === $rawDecrypter) {
            $rawDecrypter = RawPasswordDecrypter::instance();
        }
        if (null === $transformFactory) {
            $transformFactory = PasswordDecryptTransformFactory::instance();
        }
        if (null === $decodeTransform) {
            $decodeTransform = Base64UrlDecodeTransform::instance();
        }

        $this->rawDecrypter = $rawDecrypter;
        $this->transformFactory = $transformFactory;
        $this->decodeTransform = $decodeTransform;
    }

    /**
     * Get the raw decrypter.
     *
     * @return PasswordDecrypterInterface The raw decrypter.
     */
    public function rawDecrypter()
    {
        return $this->rawDecrypter;
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
     * @return PasswordDecryptionResultInterface The decryption result.
     */
    public function decrypt($password, $data)
    {
        list($data, $consumed, $error) = $this->decodeTransform()
            ->transform($data, $context, true);
        if (null !== $error) {
            return new PasswordDecryptionResult(
                DecryptionResultType::INVALID_ENCODING()
            );
        }

        return $this->rawDecrypter()->decrypt($password, $data);
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
        return new DecryptStream(
            new CompoundTransform(
                array(
                    $this->decodeTransform(),
                    $this->transformFactory()->createTransform($password),
                )
            )
        );
    }

    private static $instance;
    private $rawDecrypter;
    private $transformFactory;
    private $decodeTransform;
}
