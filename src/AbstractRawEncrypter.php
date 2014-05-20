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
use Eloquent\Lockbox\Cipher\Parameters\CipherParametersInterface;
use Eloquent\Lockbox\Stream\CipherStream;
use Eloquent\Lockbox\Stream\CipherStreamInterface;

/**
 * An abstract base class for implementing raw encrypters.
 */
abstract class AbstractRawEncrypter implements EncrypterInterface
{
    /**
     * Construct a new raw encrypter.
     *
     * @param CipherFactoryInterface $cipherFactory The cipher factory to use.
     */
    public function __construct(CipherFactoryInterface $cipherFactory)
    {
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
     * @param CipherParametersInterface $parameters The parameters to encrypt with.
     * @param string                    $data       The data to encrypt.
     *
     * @return string The encrypted data.
     */
    public function encrypt(CipherParametersInterface $parameters, $data)
    {
        $cipher = $this->cipherFactory()->createCipher();
        $cipher->initialize($parameters);

        return $cipher->finalize($data);
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
        $cipher = $this->cipherFactory()->createCipher();
        $cipher->initialize($parameters);

        return new CipherStream($cipher);
    }

    private $cipherFactory;
}
