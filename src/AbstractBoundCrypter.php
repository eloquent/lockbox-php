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
 * An abstract base class for implementing bound crypters.
 */
abstract class AbstractBoundCrypter implements BoundCrypterInterface
{
    /**
     * Construct a new bound crypter.
     *
     * @param CipherParametersInterface $encryptParameters The parameters to use when encrypting.
     * @param CipherParametersInterface $decryptParameters The parameters to use when decrypting.
     * @param CrypterInterface          $crypter           The crypter to use.
     */
    public function __construct(
        CipherParametersInterface $encryptParameters,
        CipherParametersInterface $decryptParameters,
        CrypterInterface $crypter
    ) {
        $this->encryptParameters = $encryptParameters;
        $this->decryptParameters = $decryptParameters;
        $this->crypter = $crypter;
    }

    /**
     * Get the encrypt parameters.
     *
     * @return CipherParametersInterface The encrypt parameters.
     */
    public function encryptParameters()
    {
        return $this->encryptParameters;
    }

    /**
     * Get the decrypt parameters.
     *
     * @return CipherParametersInterface The decrypt parameters.
     */
    public function decryptParameters()
    {
        return $this->decryptParameters;
    }

    /**
     * Get the crypter.
     *
     * @return CrypterInterface The crypter.
     */
    public function crypter()
    {
        return $this->crypter;
    }

    /**
     * Encrypt a data packet.
     *
     * @param string $data The data to encrypt.
     *
     * @return string The encrypted data.
     */
    public function encrypt($data)
    {
        return $this->crypter()->encrypt($this->encryptParameters(), $data);
    }

    /**
     * Decrypt a data packet.
     *
     * @param string $data The data to decrypt.
     *
     * @return CipherResultInterface The decrypt result.
     */
    public function decrypt($data)
    {
        return $this->crypter()->decrypt($this->decryptParameters(), $data);
    }

    /**
     * Create a new encrypt stream.
     *
     * @return CipherStreamInterface The newly created encrypt stream.
     */
    public function createEncryptStream()
    {
        return $this->crypter()
            ->createEncryptStream($this->encryptParameters());
    }

    /**
     * Create a new decrypt stream.
     *
     * @return CipherStreamInterface The newly created decrypt stream.
     */
    public function createDecryptStream()
    {
        return $this->crypter()
            ->createDecryptStream($this->decryptParameters());
    }

    private $encryptParameters;
    private $decryptParameters;
    private $crypter;
}
