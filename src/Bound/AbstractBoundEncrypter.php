<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Bound;

use Eloquent\Lockbox\Cipher\Parameters\CipherParametersInterface;
use Eloquent\Lockbox\EncrypterInterface;
use Eloquent\Lockbox\Stream\CipherStreamInterface;

/**
 * An abstract base class for implementing bound encrypters.
 */
abstract class AbstractBoundEncrypter implements BoundEncrypterInterface
{
    /**
     * Construct a new bound encrypter.
     *
     * @param CipherParametersInterface $parameters The parameters to use.
     * @param EncrypterInterface        $encrypter  The encrypter to use.
     */
    public function __construct(
        CipherParametersInterface $parameters,
        EncrypterInterface $encrypter
    ) {
        $this->parameters = $parameters;
        $this->encrypter = $encrypter;
    }

    /**
     * Get the parameters.
     *
     * @return CipherParametersInterface The parameters.
     */
    public function parameters()
    {
        return $this->parameters;
    }

    /**
     * Get the encrypter.
     *
     * @return EncrypterInterface The encrypter;
     */
    public function encrypter()
    {
        return $this->encrypter;
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
        return $this->encrypter()->encrypt($this->parameters(), $data);
    }

    /**
     * Create a new encrypt stream.
     *
     * @return CipherStreamInterface The newly created encrypt stream.
     */
    public function createEncryptStream()
    {
        return $this->encrypter()->createEncryptStream($this->parameters());
    }

    private $parameters;
    private $encrypter;
}
