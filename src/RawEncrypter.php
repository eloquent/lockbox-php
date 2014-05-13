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

use Eloquent\Lockbox\Cipher\Factory\CipherFactoryInterface;
use Eloquent\Lockbox\Cipher\Factory\EncryptCipherFactory;
use Eloquent\Lockbox\Key\KeyInterface;
use Eloquent\Lockbox\Stream\CipherStream;

/**
 * Encrypts data and produces raw output using keys.
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
     * @param CipherFactoryInterface|null $cipherFactory The cipher factory to use.
     */
    public function __construct(CipherFactoryInterface $cipherFactory = null)
    {
        if (null === $cipherFactory) {
            $cipherFactory = EncryptCipherFactory::instance();
        }

        $this->cipherFactory = $cipherFactory;
    }

    /**
     * Get the cipher factory.
     *
     * @return CipherFactoryInterface The cipher factory.
     */
    public function cipherFactory()
    {
        return $this->cipherFactory;
    }

    /**
     * Encrypt a data packet.
     *
     * @param KeyInterface $key  The key to encrypt with.
     * @param string       $data The data to encrypt.
     *
     * @return string The encrypted data.
     */
    public function encrypt(KeyInterface $key, $data)
    {
        $cipher = $this->cipherFactory()->createCipher();
        $cipher->initialize($key);

        return $cipher->finalize($data);
    }

    /**
     * Create a new encrypt stream.
     *
     * @param KeyInterface $key The key to encrypt with.
     *
     * @return TransformStreamInterface The newly created encrypt stream.
     */
    public function createEncryptStream(KeyInterface $key)
    {
        $cipher = $this->cipherFactory()->createCipher();
        $cipher->initialize($key);

        return new CipherStream($cipher);
    }

    private static $instance;
    private $cipherFactory;
}
