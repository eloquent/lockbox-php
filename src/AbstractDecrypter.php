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
     * @param DecrypterInterface    $rawDecrypter The raw decrypter to use.
     * @param DecoderInterface|null $decoder      The decoder to use.
     */
    public function __construct(
        DecrypterInterface $rawDecrypter,
        DecoderInterface $decoder = null
    ) {
        if (null === $decoder) {
            $decoder = Base64Url::instance();
        }

        $this->rawDecrypter = $rawDecrypter;
        $this->decoder = $decoder;
    }

    /**
     * Get the raw encrypter.
     *
     * @return DecrypterInterface The raw encrypter.
     */
    public function rawDecrypter()
    {
        return $this->rawDecrypter;
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

        return $this->rawDecrypter()->decrypt($parameters, $data);
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
        $cipherStream = $this->rawDecrypter()->createDecryptStream($parameters);

        $decodeStream = $this->decoder()->createDecodeStream();
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

    private $rawDecrypter;
    private $decoder;
}
