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

use Eloquent\Endec\Base64\Base64Url;
use Eloquent\Endec\EncoderInterface;
use Eloquent\Lockbox\Cipher\Factory\CipherFactoryInterface;
use Eloquent\Lockbox\Cipher\Factory\EncryptCipherFactory;
use Eloquent\Lockbox\Key\KeyInterface;
use Eloquent\Lockbox\Stream\CipherStream;
use Eloquent\Lockbox\Stream\CipherStreamInterface;
use Eloquent\Lockbox\Stream\CompositePostCipherStream;

/**
 * Encrypts data and produces encoded output using keys.
 */
class Encrypter implements EncrypterInterface
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
     * Construct a new encrypter.
     *
     * @param CipherFactoryInterface|null $cipherFactory The cipher factory to use.
     * @param EncoderInterface|null       $encoder       The encoder to use.
     */
    public function __construct(
        CipherFactoryInterface $cipherFactory = null,
        EncoderInterface $encoder = null
    ) {
        if (null === $cipherFactory) {
            $cipherFactory = EncryptCipherFactory::instance();
        }
        if (null === $encoder) {
            $encoder = Base64Url::instance();
        }

        $this->cipherFactory = $cipherFactory;
        $this->encoder = $encoder;
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
     * Get the encoder.
     *
     * @return EncoderInterface The encoder.
     */
    public function encoder()
    {
        return $this->encoder;
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

        return $this->encoder()->encode($cipher->finalize($data));
    }

    /**
     * Create a new encrypt stream.
     *
     * @param KeyInterface $key The key to encrypt with.
     *
     * @return CipherStreamInterface The newly created encrypt stream.
     */
    public function createEncryptStream(KeyInterface $key)
    {
        $cipher = $this->cipherFactory()->createCipher();
        $cipher->initialize($key);

        $cipherStream = new CipherStream($cipher);
        $encodeStream = $this->encoder()->createEncodeStream();
        $cipherStream->pipe($encodeStream);

        return new CompositePostCipherStream($cipherStream, $encodeStream);
    }

    private static $instance;
    private $cipherFactory;
    private $encoder;
}
