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
use Eloquent\Lockbox\Cipher\Parameters\CipherParametersInterface;
use Eloquent\Lockbox\Stream\CipherStream;
use Eloquent\Lockbox\Stream\CipherStreamInterface;
use Eloquent\Lockbox\Stream\CompositePostCipherStream;

/**
 * An abstract base class for implementing encoded encrypters.
 */
abstract class AbstractEncrypter implements EncrypterInterface
{
    /**
     * Construct a new encrypter.
     *
     * @param CipherFactoryInterface $cipherFactory The cipher factory to use.
     * @param EncoderInterface|null  $encoder       The encoder to use.
     */
    public function __construct(
        CipherFactoryInterface $cipherFactory,
        EncoderInterface $encoder = null
    ) {
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
     * @param CipherParametersInterface $parameters The parameters to encrypt with.
     * @param string                    $data       The data to encrypt.
     *
     * @return string The encrypted data.
     */
    public function encrypt(CipherParametersInterface $parameters, $data)
    {
        $cipher = $this->cipherFactory()->createCipher();
        $cipher->initialize($parameters);

        return $this->encoder()->encode($cipher->finalize($data));
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
        $cipherStream = new CipherStream($cipher);

        $encodeStream = $this->encoder()->createEncodeStream();

        $cipherStream->pipe($encodeStream);

        return new CompositePostCipherStream($cipherStream, $encodeStream);
    }

    private $cipherFactory;
    private $encoder;
}
