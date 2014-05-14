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

use Eloquent\Endec\Base64\Base64Url;
use Eloquent\Endec\EncoderInterface;
use Eloquent\Lockbox\Cipher\Factory\CipherFactoryInterface;
use Eloquent\Lockbox\Password\Cipher\Factory\PasswordEncryptCipherFactory;
use Eloquent\Lockbox\Stream\CipherStream;
use Eloquent\Lockbox\Stream\CipherStreamInterface;
use Eloquent\Lockbox\Stream\CompositePostCipherStream;

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
     * Construct a new password encrypter.
     *
     * @param CipherFactoryInterface|null $cipherFactory The cipher factory to use.
     * @param EncoderInterface|null       $encoder       The encoder to use.
     */
    public function __construct(
        CipherFactoryInterface $cipherFactory = null,
        EncoderInterface $encoder = null
    ) {
        if (null === $cipherFactory) {
            $cipherFactory = PasswordEncryptCipherFactory::instance();
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
     * @param string  $password   The password to encrypt with.
     * @param integer $iterations The number of hash iterations to use.
     * @param string  $data       The data to encrypt.
     *
     * @return string The encrypted data.
     */
    public function encrypt($password, $iterations, $data)
    {
        $cipher = $this->cipherFactory()->createCipher();
        $cipher->initialize($password, $iterations);

        return $this->encoder()->encode($cipher->finalize($data));
    }

    /**
     * Create a new encrypt stream.
     *
     * @param string  $password   The password to encrypt with.
     * @param integer $iterations The number of hash iterations to use.
     *
     * @return CipherStreamInterface The newly created encrypt stream.
     */
    public function createEncryptStream($password, $iterations)
    {
        $cipher = $this->cipherFactory()->createCipher();
        $cipher->initialize($password, $iterations);
        $cipherStream = new CipherStream($cipher);

        $encodeStream = $this->encoder()->createEncodeStream();

        $cipherStream->pipe($encodeStream);

        return new CompositePostCipherStream($cipherStream, $encodeStream);
    }

    private static $instance;
    private $cipherFactory;
    private $encoder;
}
