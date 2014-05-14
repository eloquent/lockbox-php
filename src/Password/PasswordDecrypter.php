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

use Eloquent\Endec\Base64\Base64Url;
use Eloquent\Endec\DecoderInterface;
use Eloquent\Endec\Exception\EncodingExceptionInterface;
use Eloquent\Lockbox\Cipher\Factory\CipherFactoryInterface;
use Eloquent\Lockbox\Cipher\Result\CipherResultType;
use Eloquent\Lockbox\Password\Cipher\Factory\PasswordDecryptCipherFactory;
use Eloquent\Lockbox\Password\Cipher\Result\PasswordDecryptionResult;
use Eloquent\Lockbox\Password\Cipher\Result\PasswordDecryptionResultInterface;
use Eloquent\Lockbox\Stream\CipherStream;
use Eloquent\Lockbox\Stream\CipherStreamInterface;
use Eloquent\Lockbox\Stream\CompositePreCipherStream;

/**
 * Decrypts encoded data using passwords.
 */
class PasswordDecrypter implements PasswordDecrypterInterface
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
     * Construct a new password decrypter.
     *
     * @param CipherFactoryInterface|null $cipherFactory The cipher factory to use.
     * @param DecoderInterface|null       $decoder       The decoder to use.
     */
    public function __construct(
        CipherFactoryInterface $cipherFactory = null,
        DecoderInterface $decoder = null
    ) {
        if (null === $cipherFactory) {
            $cipherFactory = PasswordDecryptCipherFactory::instance();
        }
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
     * @param string $password The password to decrypt with.
     * @param string $data     The data to decrypt.
     *
     * @return PasswordDecryptionResultInterface The decryption result.
     */
    public function decrypt($password, $data)
    {
        try {
            $data = $this->decoder()->decode($data);
        } catch (EncodingExceptionInterface $e) {
            return new PasswordDecryptionResult(
                CipherResultType::INVALID_ENCODING()
            );
        }

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
        $decodeStream = $this->decoder()->createDecodeStream();

        $cipher = $this->cipherFactory()->createCipher();
        $cipher->initialize($password);
        $cipherStream = new CipherStream($cipher);

        $decodeStream->pipe($cipherStream);

        return new CompositePreCipherStream($cipherStream, $decodeStream);
    }

    private static $instance;
    private $cipherFactory;
    private $decoder;
}
