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
use Eloquent\Confetti\TransformStream;
use Eloquent\Confetti\TransformStreamInterface;
use Eloquent\Endec\Base64\Base64UrlDecodeTransform;
use Eloquent\Endec\Exception\EncodingExceptionInterface;
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
     * @param KeyTransformFactoryInterface|null $transformFactory The transform factory to use.
     * @param TransformInterface|null           $decodeTransform  The decode transform to use.
     */
    public function __construct(
        KeyTransformFactoryInterface $transformFactory = null,
        TransformInterface $decodeTransform = null
    ) {
        if (null === $transformFactory) {
            $transformFactory = DecryptTransformFactory::instance();
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
     * @return string                              The decrypted data.
     * @throws Exception\DecryptionFailedException If the decryption failed.
     */
    public function decrypt(Key\KeyInterface $key, $data)
    {
        try {
            list($data) = $this->decodeTransform()
                ->transform($data, $context, true);
        } catch (EncodingExceptionInterface $e) {
            throw new Exception\DecryptionFailedException($key, $e);
        }

        $context = null;
        list($data) = $this->transformFactory()
            ->createTransform($key)
            ->transform($data, $context, true);

        return $data;
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
        return new TransformStream(
            new CompoundTransform(
                array(
                    $this->decodeTransform(),
                    $this->transformFactory()->createTransform($key),
                )
            )
        );
    }

    private static $instance;
    private $transformFactory;
    private $decodeTransform;
}
