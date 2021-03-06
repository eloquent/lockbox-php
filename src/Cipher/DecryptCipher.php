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
use Eloquent\Lockbox\Cipher\Parameters\EncryptParametersInterface;
use Eloquent\Lockbox\Cipher\Result\CipherResultInterface;
use Eloquent\Lockbox\Cipher\Result\CipherResultType;
use Eloquent\Lockbox\Cipher\Result\Factory\CipherResultFactory;
use Eloquent\Lockbox\Cipher\Result\Factory\CipherResultFactoryInterface;
use Eloquent\Lockbox\Comparator\SlowStringComparator;
use Eloquent\Lockbox\Key\KeyInterface;
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
     * @param UnpadderInterface|null            $unpadder      The unpadder to use.
     * @param CipherResultFactoryInterface|null $resultFactory The result factory to use.
     */
    public function __construct(
        UnpadderInterface $unpadder = null,
        CipherResultFactoryInterface $resultFactory = null
    ) {
        if (null === $unpadder) {
            $unpadder = PkcsPadding::instance();
        }
        if (null === $resultFactory) {
            $resultFactory = CipherResultFactory::instance();
        }

        $this->unpadder = $unpadder;
        $this->resultFactory = $resultFactory;

        $this->deinitialize();
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
     * Get the result factory.
     *
     * @return CipherResultFactoryInterface The result factory.
     */
    public function resultFactory()
    {
        return $this->resultFactory;
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
        if ($parameters instanceof KeyInterface) {
            $this->key = $parameters;
        } elseif ($parameters instanceof EncryptParametersInterface) {
            $this->key = $parameters->key();
        } else {
            throw new UnsupportedCipherParametersException($this, $parameters);
        }

        $this->isInitialized = true;

        $this->mcryptModule = mcrypt_module_open(
            MCRYPT_RIJNDAEL_128,
            '',
            MCRYPT_MODE_CBC,
            ''
        );
        $this->isMcryptInitialized = false;

        $this->hashContext = hash_init(
            'sha' . $this->key->authSecretBits(),
            HASH_HMAC,
            $this->key->authSecret()
        );
        $this->macSize = $this->key->authSecretBytes();

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
            throw new CipherNotInitializedException($this);
        }
        if ($this->isFinalized) {
            throw new CipherFinalizedException($this);
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
            throw new CipherNotInitializedException($this);
        }
        if ($this->isFinalized) {
            throw new CipherFinalizedException($this);
        }

        $this->isFinalized = true;

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

        $this->processHeader($size);

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
        $this->result = null;

        if ($this->isMcryptInitialized) {
            mcrypt_generic_deinit($this->mcryptModule);
        }
        $this->isMcryptInitialized = false;

        if (null !== $this->hashContext) {
            $this->finalHashContext = hash_copy($this->hashContext);
        }
    }

    /**
     * Reset this cipher to its initial state, and clear any sensitive data.
     */
    public function deinitialize()
    {
        if ($this->isMcryptInitialized) {
            mcrypt_generic_deinit($this->mcryptModule);
        }

        unset($this->key);
        unset($this->macSize);
        unset($this->mcryptModule);
        unset($this->hashContext);
        unset($this->finalHashContext);
        unset($this->buffer);
        unset($this->result);

        $this->key = $this->macSize = $this->mcryptModule = $this->hashContext =
            $this->finalHashContext = $this->result = null;
        $this->isInitialized = $this->isHeaderReceived = $this->isFinalized =
            $this->isMcryptInitialized = false;
        $this->buffer = '';
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
            $this->key->encryptSecret(),
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
            $this->result = $this->resultFactory()->createResult($type);
        }
    }

    private $unpadder;
    private $resultFactory;
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
