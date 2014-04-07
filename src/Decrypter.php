<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox;

use Eloquent\Confetti\CompoundTransform;
use Eloquent\Confetti\TransformInterface;
use Eloquent\Confetti\TransformStreamInterface;
use Eloquent\Endec\Base64\Base64UrlDecodeTransform;
use Eloquent\Lockbox\Result\DecryptionResult;
use Eloquent\Lockbox\Result\DecryptionResultInterface;
use Eloquent\Lockbox\Result\DecryptionResultType;
use Eloquent\Lockbox\Stream\DecryptStream;
use Eloquent\Lockbox\Transform\Factory\DecryptTransformFactory;
use Eloquent\Lockbox\Transform\Factory\KeyTransformFactoryInterface;

/**
 * Decrypts encoded data using keys.
 */
class Decrypter implements DecrypterInterface
{
    /**
     * Get the static instance of this decrypter.
     *
     * @return DecrypterInterface The static decrypter.
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
     * @param DecrypterInterface|null           $rawDecrypter     The raw decrypter to use.
     * @param KeyTransformFactoryInterface|null $transformFactory The transform factory to use.
     * @param TransformInterface|null           $decodeTransform  The decode transform to use.
     */
    public function __construct(
        DecrypterInterface $rawDecrypter = null,
        KeyTransformFactoryInterface $transformFactory = null,
        TransformInterface $decodeTransform = null
    ) {
        if (null === $rawDecrypter) {
            $rawDecrypter = RawDecrypter::instance();
        }
        if (null === $transformFactory) {
            $transformFactory = DecryptTransformFactory::instance();
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
     * @return DecrypterInterface The raw decrypter.
     */
    public function rawDecrypter()
    {
        return $this->rawDecrypter;
    }

    /**
     * Get the transform factory.
     *
     * @return KeyTransformFactoryInterface The transform factory.
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
     * @param Key\KeyInterface $key  The key to decrypt with.
     * @param string           $data The data to decrypt.
     *
     * @return DecryptionResultInterface The decryption result.
     */
    public function decrypt(Key\KeyInterface $key, $data)
    {
        list($data, $consumed, $error) = $this->decodeTransform()
            ->transform($data, $context, true);
        if (null !== $error) {
            return new DecryptionResult(
                DecryptionResultType::INVALID_ENCODING()
            );
        }

        return $this->rawDecrypter()->decrypt($key, $data);
    }

    /**
     * Create a new decrypt stream.
     *
     * @param Key\KeyInterface $key The key to decrypt with.
     *
     * @return TransformStreamInterface The newly created decrypt stream.
     */
    public function createDecryptStream(Key\KeyInterface $key)
    {
        return new DecryptStream(
            new CompoundTransform(
                array(
                    $this->decodeTransform(),
                    $this->transformFactory()->createTransform($key),
                )
            )
        );
    }

    private static $instance;
    private $rawDecrypter;
    private $transformFactory;
    private $decodeTransform;
}
