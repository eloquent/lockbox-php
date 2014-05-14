<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Cipher;

use Eloquent\Lockbox\Cipher\Exception\CipherFinalizedException;
use Eloquent\Lockbox\Cipher\Exception\CipherNotInitializedException;
use Eloquent\Lockbox\Cipher\Exception\CipherStateExceptionInterface;
use Eloquent\Lockbox\Cipher\Exception\UnsupportedCipherParametersException;
use Eloquent\Lockbox\Cipher\Parameters\CipherParametersInterface;
use Eloquent\Lockbox\Cipher\Parameters\DecryptCipherParametersInterface;
use Eloquent\Lockbox\Cipher\Result\CipherResult;
use Eloquent\Lockbox\Cipher\Result\CipherResultInterface;
use Eloquent\Lockbox\Cipher\Result\CipherResultType;
use Eloquent\Lockbox\Comparator\SlowStringComparator;
use Eloquent\Lockbox\Padding\PkcsPadding;
use Eloquent\Lockbox\Padding\UnpadderInterface;

/**
 * Decrypts data with a key.
 */
class DecryptCipher implements CipherInterface
{
    /**
     * Construct a new decrypt cipher.
     *
     * @param UnpadderInterface|null $unpadder The unpadder to use.
     */
    public function __construct(UnpadderInterface $unpadder = null)
    {
        if (null === $unpadder) {
            $unpadder = PkcsPadding::instance();
        }

        $this->unpadder = $unpadder;
        $this->isInitialized = false;

        $this->reset();
    }

    /**
     * Get the unpadder.
     *
     * @return UnpadderInterface The unpadder.
     */
    public function unpadder()
    {
        return $this->unpadder;
    }

    /**
     * Initialize this cipher.
     *
     * @param CipherParametersInterface $parameters The parameters to use.
     *
     * @throws UnsupportedCipherParametersException If unsupported parameters are supplied.
     */
    public function initialize(CipherParametersInterface $parameters)
    {
        if (!$parameters instanceof DecryptCipherParametersInterface) {
            throw new UnsupportedCipherParametersException($parameters);
        }

        $this->isInitialized = true;
        $this->key = $parameters->key();

        $this->mcryptModule = mcrypt_module_open(
            MCRYPT_RIJNDAEL_128,
            '',
            MCRYPT_MODE_CBC,
            ''
        );

        $this->hashContext = hash_init(
            'sha' . $this->key->authenticationSecretBits(),
            HASH_HMAC,
            $this->key->authenticationSecret()
        );
        $this->macSize = $this->key->authenticationSecretBytes();

        $this->reset();
    }

    /**
     * Returns true if this cipher is initialized.
     *
     * @return boolean True if initialized.
     */
    public function isInitialized()
    {
        return $this->isInitialized;
    }

    /**
     * Process the supplied input data.
     *
     * This method may be called repeatedly with additional data.
     *
     * @param string $input The data to process.
     *
     * @return string                        Any output produced.
     * @throws CipherStateExceptionInterface If the cipher is in an invalid state.
     */
    public function process($input)
    {
        if (!$this->isInitialized) {
            throw new CipherNotInitializedException;
        }
        if ($this->isFinalized) {
            throw new CipherFinalizedException;
        }

        $this->buffer .= $input;
        $size = strlen($this->buffer);

        if (!$this->processHeader($size)) {
            return '';
        }
        if ($size < 36 + $this->macSize) {
            return '';
        }

        $size -= 18 + $this->macSize;
        $consume = $size - ($size % 18);
        if (!$consume) {
            return '';
        }

        $input = substr($this->buffer, 0, $consume);
        $this->buffer = substr($this->buffer, $consume);

        return $this->decryptBlocks($input);
    }

    /**
     * Finalize processing and return any remaining output.
     *
     * @param string|null $input Any remaining data to process.
     *
     * @return string                        Any output produced.
     * @throws CipherStateExceptionInterface If the cipher is in an invalid state.
     */
    public function finalize($input = null)
    {
        if (!$this->isInitialized) {
            throw new CipherNotInitializedException;
        }
        if ($this->isFinalized) {
            throw new CipherFinalizedException;
        }

        if (null !== $input) {
            $this->buffer .= $input;
        }
        $input = null;
        $size = strlen($this->buffer);

        if ($this->isHeaderReceived) {
            $requiredSize = 18 + $this->macSize;
            $ciphertextSize = $size - $this->macSize;
        } else {
            $requiredSize = 36 + $this->macSize;
            $ciphertextSize = $size - 18 - $this->macSize;
        }

        if ($size < $requiredSize || 0 !== $ciphertextSize % 18) {
            $this->setResult(CipherResultType::INVALID_SIZE());

            return '';
        }
        if (!$this->isHeaderReceived && !$this->preCheck($size)) {
            return '';
        }
        if (!$this->processHeader($size)) {
            return '';
        }

        $ciphertext = substr($this->buffer, 0, $ciphertextSize);
        $mac = substr($this->buffer, $ciphertextSize);
        $this->buffer = '';

        $output = $this->decryptBlocks($ciphertext);

        if (
            !SlowStringComparator::isEqual(
                hash_final($this->finalHashContext, true),
                $mac
            )
        ) {
            $this->setResult(CipherResultType::INVALID_MAC());

            return '';
        }

        list($isSuccessful, $output) = $this->unpadder()->unpad($output);
        if (!$isSuccessful) {
            $this->setResult(CipherResultType::INVALID_PADDING());

            return '';
        }

        $this->setResult(CipherResultType::SUCCESS());

        return $output;
    }

    /**
     * Returns true if this cipher is finalized.
     *
     * @return boolean True if finalized.
     */
    public function isFinalized()
    {
        return $this->isFinalized;
    }

    /**
     * Returns true if this cipher has produced a result.
     *
     * @return boolean True if a result is available.
     */
    public function hasResult()
    {
        return null !== $this->result;
    }

    /**
     * Get the result.
     *
     * @return CipherResultInterface|null The result, if available.
     */
    public function result()
    {
        return $this->result;
    }

    /**
     * Reset this cipher to the state just after the last initialize() call.
     */
    public function reset()
    {
        $this->isHeaderReceived = $this->isFinalized = false;
        $this->buffer = '';

        if ($this->isMcryptInitialized) {
            mcrypt_generic_deinit($this->mcryptModule);
        }
        $this->isMcryptInitialized = false;

        if (null !== $this->hashContext) {
            $this->finalHashContext = hash_copy($this->hashContext);
        }
    }

    /**
     * Create a new cipher result of the supplied type.
     *
     * @param CipherResultType $type The result type.
     *
     * @return CipherResultInterface The newly created cipher result.
     */
    protected function createResult(CipherResultType $type)
    {
        return new CipherResult($type);
    }

    private function processHeader(&$size)
    {
        if ($this->isHeaderReceived) {
            return true;
        }
        if ($size < 18) {
            return false;
        }

        $this->isHeaderReceived = true;

        if (18 === $size) {
            $header = $this->buffer;
            $this->buffer = '';
        } else {
            $header = substr($this->buffer, 0, 18);
            $this->buffer = substr($this->buffer, 18);
        }

        $size -= 18;

        if (1 !== ord($header[0])) {
            $this->setResult(CipherResultType::UNSUPPORTED_VERSION());
        } elseif (1 !== ord($header[1])) {
            $this->setResult(CipherResultType::UNSUPPORTED_TYPE());
        }

        mcrypt_generic_init(
            $this->mcryptModule,
            $this->key->encryptionSecret(),
            substr($header, 2, 16)
        );
        $this->isMcryptInitialized = true;

        hash_update($this->finalHashContext, $header);

        return true;
    }

    private function decryptBlocks($input)
    {
        $output = '';
        foreach (str_split($input, 18) as $block) {
            list($block, $mac) = str_split($block, 16);

            $hashContext = hash_copy($this->hashContext);
            hash_update($hashContext, $block);

            if (
                !SlowStringComparator::isEqual(
                    substr(hash_final($hashContext, true), 0, 2),
                    $mac
                )
            ) {
                $this->setResult(CipherResultType::INVALID_MAC());
            }

            hash_update($this->finalHashContext, $block);
            $output .= mdecrypt_generic($this->mcryptModule, $block);
        }

        return $output;
    }

    private function preCheck($size)
    {
        $header = substr($this->buffer, 0, 18);
        $ciphertext = substr($this->buffer, 18, $size - 18 - $this->macSize);
        $mac = substr($this->buffer, $size - $this->macSize);

        $hashContext = hash_copy($this->hashContext);
        hash_update($hashContext, $header);

        foreach (str_split($ciphertext, 18) as $block) {
            list($block) = str_split($block, 16);
            hash_update($hashContext, $block);
        }

        if (
            !SlowStringComparator::isEqual(hash_final($hashContext, true), $mac)
        ) {
            $this->setResult(CipherResultType::INVALID_MAC());

            return false;
        }

        return true;
    }

    private function setResult(CipherResultType $type)
    {
        if (!$this->result) {
            $this->result = $this->createResult($type);
        }
    }

    private $unpadder;
    private $isInitialized;
    private $key;
    private $macSize;
    private $isHeaderReceived;
    private $isFinalized;
    private $mcryptModule;
    private $isMcryptInitialized;
    private $hashContext;
    private $finalHashContext;
    private $buffer;
    private $result;
}
