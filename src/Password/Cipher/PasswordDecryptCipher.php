<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Password\Cipher;

use Eloquent\Lockbox\Cipher\CipherInterface;
use Eloquent\Lockbox\Cipher\Exception\CipherFinalizedException;
use Eloquent\Lockbox\Cipher\Exception\CipherNotInitializedException;
use Eloquent\Lockbox\Cipher\Exception\CipherStateExceptionInterface;
use Eloquent\Lockbox\Cipher\Exception\UnsupportedCipherParametersException;
use Eloquent\Lockbox\Cipher\Parameters\CipherParametersInterface;
use Eloquent\Lockbox\Cipher\Result\CipherResultInterface;
use Eloquent\Lockbox\Cipher\Result\CipherResultType;
use Eloquent\Lockbox\Cipher\Result\Factory\CipherResultFactoryInterface;
use Eloquent\Lockbox\Comparator\SlowStringComparator;
use Eloquent\Lockbox\Key\KeyDeriver;
use Eloquent\Lockbox\Key\KeyDeriverInterface;
use Eloquent\Lockbox\Padding\PkcsPadding;
use Eloquent\Lockbox\Padding\UnpadderInterface;
use Eloquent\Lockbox\Password\Cipher\Parameters\PasswordEncryptParametersInterface;
use Eloquent\Lockbox\Password\Cipher\Result\Factory\PasswordDecryptResultFactory;
use Eloquent\Lockbox\Password\PasswordInterface;

/**
 * Decrypts data with a password.
 */
class PasswordDecryptCipher implements CipherInterface
{
    /**
     * Construct a new password decrypt cipher.
     *
     * @param integer|null                      $maxIterations The maximum number of hash iterations to allow.
     * @param KeyDeriverInterface|null          $keyDeriver    The key deriver to use.
     * @param UnpadderInterface|null            $unpadder      The unpadder to use.
     * @param CipherResultFactoryInterface|null $resultFactory The result factory to use.
     */
    public function __construct(
        $maxIterations = null,
        KeyDeriverInterface $keyDeriver = null,
        UnpadderInterface $unpadder = null,
        CipherResultFactoryInterface $resultFactory = null
    ) {
        if (null === $maxIterations) {
            $maxIterations = 4194304;
        }
        if (null === $keyDeriver) {
            $keyDeriver = KeyDeriver::instance();
        }
        if (null === $unpadder) {
            $unpadder = PkcsPadding::instance();
        }
        if (null === $resultFactory) {
            $resultFactory = PasswordDecryptResultFactory::instance();
        }

        $this->maxIterations = $maxIterations;
        $this->keyDeriver = $keyDeriver;
        $this->unpadder = $unpadder;
        $this->resultFactory = $resultFactory;

        $this->deinitialize();
    }

    /**
     * Get the maximum number of hash iterations.
     *
     * @return integer The maximum iterations.
     */
    public function maxIterations()
    {
        return $this->maxIterations;
    }

    /**
     * Get the key deriver.
     *
     * @return KeyDeriverInterface The key deriver.
     */
    public function keyDeriver()
    {
        return $this->keyDeriver;
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
        if ($parameters instanceof PasswordInterface) {
            $this->password = $parameters;
        } elseif ($parameters instanceof PasswordEncryptParametersInterface) {
            $this->password = $parameters->password();
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
        if ($size < 68) {
            return '';
        }

        $size -= 50;
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
            $requiredSize = 50;
            $ciphertextSize = $size - 32;
        } else {
            $requiredSize = 136;
            $ciphertextSize = $size - 118;
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

        $this->hashContext = $this->finalHashContext = null;
    }

    /**
     * Reset this cipher to its initial state, and clear any sensitive data.
     */
    public function deinitialize()
    {
        if ($this->isMcryptInitialized) {
            mcrypt_generic_deinit($this->mcryptModule);
        }

        unset($this->password);
        unset($this->iterations);
        unset($this->key);
        unset($this->mcryptModule);
        unset($this->hashContext);
        unset($this->finalHashContext);
        unset($this->buffer);
        unset($this->result);

        $this->password = $this->iterations = $this->key = $this->mcryptModule =
            $this->hashContext = $this->finalHashContext = $this->result = null;
        $this->isInitialized = $this->isHeaderReceived = $this->isFinalized =
            $this->isMcryptInitialized = false;
        $this->buffer = '';
    }

    private function processHeader(&$size)
    {
        if ($this->isHeaderReceived) {
            return true;
        }
        if ($size < 86) {
            return false;
        }

        $this->isHeaderReceived = true;

        if (86 === $size) {
            $header = $this->buffer;
            $this->buffer = '';
        } else {
            $header = substr($this->buffer, 0, 86);
            $this->buffer = substr($this->buffer, 86);
        }

        $size -= 86;

        if (1 !== ord($header[0])) {
            $this->setResult(CipherResultType::UNSUPPORTED_VERSION());
        } elseif (2 !== ord($header[1])) {
            $this->setResult(CipherResultType::UNSUPPORTED_TYPE());
        }

        list(, $this->iterations) = unpack('N', substr($header, 2, 4));

        if ($this->iterations > $this->maxIterations) {
            $this->setResult(CipherResultType::TOO_MANY_ITERATIONS());
            $this->iterations = 1;
        }

        list($this->key) = $this->keyDeriver()->deriveKeyFromPassword(
            $this->password,
            $this->iterations,
            substr($header, 6, 64)
        );

        mcrypt_generic_init(
            $this->mcryptModule,
            $this->key->encryptSecret(),
            substr($header, 70, 16)
        );
        $this->isMcryptInitialized = true;

        $this->hashContext =
            hash_init('sha256', HASH_HMAC, $this->key->authSecret());
        $this->finalHashContext = hash_copy($this->hashContext);
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
        $header = substr($this->buffer, 0, 86);
        $ciphertext = substr($this->buffer, 86, $size - 118);
        $mac = substr($this->buffer, $size - 32);

        list(, $iterations) = unpack('N', substr($header, 2, 4));

        if ($iterations > $this->maxIterations) {
            $this->setResult(CipherResultType::TOO_MANY_ITERATIONS());

            return false;
        }

        list($key) = $this->keyDeriver()->deriveKeyFromPassword(
            $this->password,
            $iterations,
            substr($header, 6, 64)
        );

        $hashContext = hash_init('sha256', HASH_HMAC, $key->authSecret());
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

            if (CipherResultType::SUCCESS() === $type) {
                $this->result->setIterations($this->iterations);
            }
        }
    }

    private $maxIterations;
    private $keyDeriver;
    private $unpadder;
    private $resultFactory;
    private $isInitialized;
    private $password;
    private $iterations;
    private $key;
    private $isHeaderReceived;
    private $isFinalized;
    private $mcryptModule;
    private $isMcryptInitialized;
    private $hashContext;
    private $finalHashContext;
    private $buffer;
    private $result;
}
