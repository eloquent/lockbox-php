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

use Eloquent\Lockbox\Cipher\Factory\CipherFactoryInterface;
use Eloquent\Lockbox\Password\Cipher\Factory\PasswordEncryptCipherFactory;
use Eloquent\Lockbox\Stream\CipherStream;
use Eloquent\Lockbox\Stream\CipherStreamInterface;

/**
 * Encrypts data and produces raw output using passwords.
 */
class RawPasswordEncrypter implements PasswordEncrypterInterface
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
     * Construct a new raw password encrypter.
     *
     * @param CipherFactoryInterface|null $cipherFactory The cipher factory to use.
     */
    public function __construct(
        CipherFactoryInterface $cipherFactory = null
    ) {
        if (null === $cipherFactory) {
            $cipherFactory = PasswordEncryptCipherFactory::instance();
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

        return $cipher->finalize($data);
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

        return new CipherStream($cipher);
    }

    private static $instance;
    private $cipherFactory;
}
