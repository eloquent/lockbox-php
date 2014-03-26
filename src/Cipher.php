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

/**
 * The standard Lockbox cipher.
 */
class Cipher implements CipherInterface
{
    /**
     * Get the static instance of this cipher.
     *
     * @return CipherInterface The static cipher.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new cipher.
     *
     * @param EncrypterInterface|null $encrypter The encrypter to use.
     * @param DecrypterInterface|null $decrypter The decrypter to use.
     */
    public function __construct(
        EncrypterInterface $encrypter = null,
        DecrypterInterface $decrypter = null
    ) {
        if (null === $encrypter) {
            $encrypter = Encrypter::instance();
        }
        if (null === $decrypter) {
            $decrypter = Decrypter::instance();
        }

        $this->encrypter = $encrypter;
        $this->decrypter = $decrypter;
    }

    /**
     * Get the encrypter.
     *
     * @return EncrypterInterface The encrypter.
     */
    public function encrypter()
    {
        return $this->encrypter;
    }

    /**
     * Get the decrypter.
     *
     * @return DecrypterInterface The decrypter.
     */
    public function decrypter()
    {
        return $this->decrypter;
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
        return $this->encrypter()->encrypt($key, $data);
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
        return $this->decrypter()->decrypt($key, $data);
    }

    private static $instance;
    private $encrypter;
    private $decrypter;
}
