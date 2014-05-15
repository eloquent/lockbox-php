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

use Eloquent\Lockbox\Cipher\Parameters\CipherParametersInterface;
use Eloquent\Lockbox\Cipher\Result\CipherResultInterface;
use Eloquent\Lockbox\Stream\CipherStreamInterface;

/**
 * An abstract base class for implementing crypters.
 */
abstract class AbstractCrypter implements CrypterInterface
{
    /**
     * Construct a new crypter.
     *
     * @param EncrypterInterface $encrypter The encrypter to use.
     * @param DecrypterInterface $decrypter The decrypter to use.
     */
    public function __construct(
        EncrypterInterface $encrypter,
        DecrypterInterface $decrypter
    ) {
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
     * @param CipherParametersInterface $parameters The parameters to encrypt with.
     * @param string                    $data       The data to encrypt.
     *
     * @return string The encrypted data.
     */
    public function encrypt(CipherParametersInterface $parameters, $data)
    {
        return $this->encrypter()->encrypt($parameters, $data);
    }

    /**
     * Decrypt a data packet.
     *
     * @param CipherParametersInterface $parameters The parameters to decrypt with.
     * @param string                    $data       The data to decrypt.
     *
     * @return CipherResultInterface The decryption result.
     */
    public function decrypt(CipherParametersInterface $parameters, $data)
    {
        return $this->decrypter()->decrypt($parameters, $data);
    }

    /**
     * Create a new encrypt stream.
     *
     * @param CipherParametersInterface $parameters The parameters to encrypt with.
     *
     * @return CipherStreamInterface The newly created encrypt stream.
     */
    public function createEncryptStream(CipherParametersInterface $parameters)
    {
        return $this->encrypter()->createEncryptStream($parameters);
    }

    /**
     * Create a new decrypt stream.
     *
     * @param CipherParametersInterface $parameters The parameters to decrypt with.
     *
     * @return CipherStreamInterface The newly created decrypt stream.
     */
    public function createDecryptStream(CipherParametersInterface $parameters)
    {
        return $this->decrypter()->createDecryptStream($parameters);
    }

    private $encrypter;
    private $decrypter;
}
