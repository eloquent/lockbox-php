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
use Eloquent\Endec\DecoderInterface;
use Eloquent\Endec\Exception\EncodingExceptionInterface;
use Eloquent\Lockbox\Cipher\Factory\CipherFactoryInterface;
use Eloquent\Lockbox\Cipher\Parameters\CipherParametersInterface;
use Eloquent\Lockbox\Cipher\Result\CipherResultInterface;
use Eloquent\Lockbox\Cipher\Result\CipherResultType;
use Eloquent\Lockbox\Stream\CipherStream;
use Eloquent\Lockbox\Stream\CipherStreamInterface;
use Eloquent\Lockbox\Stream\CompositePreCipherStream;

/**
 * An abstract base class for implementing encoded decrypters.
 */
abstract class AbstractDecrypter implements DecrypterInterface
{
    /**
     * Construct a new decrypter.
     *
     * @param CipherFactoryInterface $cipherFactory The cipher factory to use.
     * @param DecoderInterface|null  $decoder       The decoder to use.
     */
    public function __construct(
        CipherFactoryInterface $cipherFactory,
        DecoderInterface $decoder = null
    ) {
        if (null === $decoder) {
            $decoder = Base64Url::instance();
        }

        $this->cipherFactory = $cipherFactory;
        $this->decoder = $decoder;
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
     * Get the decoder.
     *
     * @return DecoderInterface The decoder.
     */
    public function decoder()
    {
        return $this->decoder;
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
        try {
            $data = $this->decoder()->decode($data);
        } catch (EncodingExceptionInterface $e) {
            return $this->createResult(CipherResultType::INVALID_ENCODING());
        }

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
        $decodeStream = $this->decoder()->createDecodeStream();

        $cipher = $this->cipherFactory()->createCipher();
        $cipher->initialize($parameters);
        $cipherStream = new CipherStream($cipher);

        $decodeStream->pipe($cipherStream);

        return new CompositePreCipherStream($cipherStream, $decodeStream);
    }

    /**
     * Create a new cipher result of the supplied type.
     *
     * @param CipherResultType $type The result type.
     *
     * @return CipherResultInterface The newly created cipher result.
     */
    abstract protected function createResult(CipherResultType $type);

    private $cipherFactory;
    private $decoder;
}
