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
use Eloquent\Lockbox\Cipher\Factory\DecryptCipherFactory;
use Eloquent\Lockbox\Cipher\Parameters\CipherParametersInterface;
use Eloquent\Lockbox\Cipher\Result\CipherResultInterface;
use Eloquent\Lockbox\Stream\CipherStream;
use Eloquent\Lockbox\Stream\CipherStreamInterface;

/**
 * An abstract base class for implementing raw decrypters.
 */
abstract class AbstractRawDecrypter implements DecrypterInterface
{
    /**
     * Construct a new raw encrypter.
     *
     * @param CipherFactoryInterface|null $cipherFactory The cipher factory to use.
     */
    public function __construct(CipherFactoryInterface $cipherFactory = null)
    {
        if (null === $cipherFactory) {
            $cipherFactory = DecryptCipherFactory::instance();
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
     * @param CipherParametersInterface $parameters The parameters to decrypt with.
     * @param string                    $data       The data to decrypt.
     *
     * @return CipherResultInterface The decryption result.
     */
    public function decrypt(CipherParametersInterface $parameters, $data)
    {
        $cipher = $this->cipherFactory()->createCipher();
        $cipher->initialize($parameters);

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
     * @param CipherParametersInterface $parameters The parameters to decrypt with.
     *
     * @return CipherStreamInterface The newly created decrypt stream.
     */
    public function createDecryptStream(CipherParametersInterface $parameters)
    {
        $cipher = $this->cipherFactory()->createCipher();
        $cipher->initialize($parameters);

        return new CipherStream($cipher);
    }

    private $cipherFactory;
}
