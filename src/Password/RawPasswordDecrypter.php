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
use Eloquent\Lockbox\Password\Cipher\Factory\PasswordDecryptCipherFactory;
use Eloquent\Lockbox\Password\Cipher\Result\PasswordDecryptionResultInterface;
use Eloquent\Lockbox\Stream\CipherStream;
use Eloquent\Lockbox\Stream\CipherStreamInterface;

/**
 * Decrypts raw data using passwords.
 */
class RawPasswordDecrypter implements PasswordDecrypterInterface
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
     * Construct a new raw password decrypter.
     *
     * @param CipherFactoryInterface|null $cipherFactory The cipher factory to use.
     */
    public function __construct(CipherFactoryInterface $cipherFactory = null)
    {
        if (null === $cipherFactory) {
            $cipherFactory = PasswordDecryptCipherFactory::instance();
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
     * Decrypt a data packet.
     *
     * @param string $password The password to decrypt with.
     * @param string $data     The data to decrypt.
     *
     * @return PasswordDecryptionResultInterface The decryption result.
     */
    public function decrypt($password, $data)
    {
        $cipher = $this->cipherFactory()->createCipher();
        $cipher->initialize($password);

        $data = $cipher->finalize($data);

        $result = $cipher->result();
        if ($result->isSuccessful()) {
            $result->setData($data);
        }

        return $result;
    }

    /**
     * Create a new decrypt stream.
     *
     * @param string $password The password to decrypt with.
     *
     * @return CipherStreamInterface The newly created decrypt stream.
     */
    public function createDecryptStream($password)
    {
        $cipher = $this->cipherFactory()->createCipher();
        $cipher->initialize($password);

        return new CipherStream($cipher);
    }

    private static $instance;
    private $cipherFactory;
}
