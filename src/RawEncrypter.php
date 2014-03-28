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

use Eloquent\Endec\Transform\TransformStream;
use Eloquent\Endec\Transform\TransformStreamInterface;
use Eloquent\Lockbox\Transform\Factory\CryptographicTransformFactoryInterface;
use Eloquent\Lockbox\Transform\Factory\EncryptTransformFactory;

/**
 * Encrypts data and produces raw output.
 */
class RawEncrypter implements EncrypterInterface
{
    /**
     * Get the static instance of this encrypter.
     *
     * @return EncrypterInterface The static encrypter.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new raw encrypter.
     *
     * @param CryptographicTransformFactoryInterface|null $transformFactory The transform factory to use.
     */
    public function __construct(
        CryptographicTransformFactoryInterface $transformFactory = null
    ) {
        if (null === $transformFactory) {
            $transformFactory = EncryptTransformFactory::instance();
        }

        $this->transformFactory = $transformFactory;
    }

    /**
     * Get the transform factory.
     *
     * @return CryptographicTransformFactoryInterface The transform factory.
     */
    public function transformFactory()
    {
        return $this->transformFactory;
    }

    /**
     * Encrypt a data packet.
     *
     * @param Key\KeyInterface $key  The key to encrypt with.
     * @param string           $data The data to encrypt.
     *
     * @return string The encrypted data.
     */
    public function encrypt(Key\KeyInterface $key, $data)
    {
        list($data) = $this->transformFactory()
            ->createTransform($key)
            ->transform($data, $context, true);

        return $data;
    }

    /**
     * Create a new encrypt stream.
     *
     * @param Key\KeyInterface $key The key to encrypt with.
     *
     * @return TransformStreamInterface The newly created encode stream.
     */
    public function createEncryptStream(Key\KeyInterface $key)
    {
        return new TransformStream(
            $this->transformFactory()->createTransform($key)
        );
    }

    private static $instance;
    private $transformFactory;
}
