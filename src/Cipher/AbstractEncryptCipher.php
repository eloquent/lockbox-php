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
use Eloquent\Lockbox\Cipher\Result\CipherResult;
use Eloquent\Lockbox\Cipher\Result\CipherResultInterface;
use Eloquent\Lockbox\Cipher\Result\CipherResultType;
use Eloquent\Lockbox\Cipher\Result\Factory\CipherResultFactory;
use Eloquent\Lockbox\Cipher\Result\Factory\CipherResultFactoryInterface;
use Eloquent\Lockbox\Key\KeyInterface;
use Eloquent\Lockbox\Padding\PadderInterface;
use Eloquent\Lockbox\Padding\PkcsPadding;
use Eloquent\Lockbox\Random\DevUrandom;
use Eloquent\Lockbox\Random\RandomSourceInterface;

/**
 * An abstract base class for implementing encrypt ciphers.
 */
abstract class AbstractEncryptCipher implements CipherInterface
{
    /**
     * Construct a new encrypt cipher.
     *
     * @param RandomSourceInterface|null        $randomSource  The random source to use.
     * @param PadderInterface|null              $padder        The padder to use.
     * @param CipherResultFactoryInterface|null $resultFactory The result factory to use.
     */
    public function __construct(
        RandomSourceInterface $randomSource = null,
        PadderInterface $padder = null,
        CipherResultFactoryInterface $resultFactory = null
    ) {
        if (null === $randomSource) {
            $randomSource = DevUrandom::instance();
        }
        if (null === $padder) {
            $padder = PkcsPadding::instance();
        }
        if (null === $resultFactory) {
            $resultFactory = CipherResultFactory::instance();
        }

        $this->randomSource = $randomSource;
        $this->padder = $padder;
        $this->resultFactory = $resultFactory;

        $this->deinitialize();
    }

    /**
     * Get the random source.
     *
     * @return RandomSourceInterface The random source.
     */
    public function randomSource()
    {
        return $this->randomSource;
    }

    /**
     * Get the padder.
     *
     * @return PadderInterface The padder.
     */
    public function padder()
    {
        return $this->padder;
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

        if ($this->isHeaderSent) {
            $output = '';
        } else {
            $this->isHeaderSent = true;
            $output = $this->header;
        }

        $this->buffer .= $input;
        $size = strlen($this->buffer);
        $consume = $size - ($size % 16);

        if (!$consume) {
            return $output;
        }

        if ($consume === $size) {
            $input = $this->buffer;
            $this->buffer = '';
        } else {
            list($input, $this->buffer) = str_split($this->buffer, $consume);
        }

        return $output .
            $this->authenticateBlocks(
                mcrypt_generic($this->mcryptModule, $input)
            );
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

        if ($this->isHeaderSent) {
            $output = '';
        } else {
            $this->isHeaderSent = true;
            $output = $this->header;
        }

        if (null !== $input) {
            $this->buffer .= $input;
        }
        $input = null;

        $output .=
            $this->authenticateBlocks(
                mcrypt_generic(
                    $this->mcryptModule,
                    $this->padder->pad($this->buffer)
                )
            ) .
            hash_final($this->finalHashContext, true);

        $this->result = new CipherResult(CipherResultType::SUCCESS());

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
        $this->isHeaderSent = $this->isFinalized = false;
        $this->result = null;
        $this->buffer = '';

        if (null !== $this->mcryptModule) {
            if ($this->isMcryptInitialized) {
                mcrypt_generic_deinit($this->mcryptModule);
            }

            $this->isMcryptInitialized = true;
            mcrypt_generic_init(
                $this->mcryptModule,
                $this->key->encryptSecret(),
                $this->iv
            );
        }

        if (null !== $this->hashContext) {
            $this->finalHashContext = hash_copy($this->hashContext);
            hash_update($this->finalHashContext, $this->header);
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
        unset($this->iv);
        unset($this->header);
        unset($this->mcryptModule);
        unset($this->hashContext);
        unset($this->finalHashContext);
        unset($this->buffer);
        unset($this->result);

        $this->key = $this->iv = $this->header = $this->mcryptModule =
            $this->hashContext = $this->finalHashContext = $this->result = null;
        $this->isInitialized = $this->isHeaderSent = $this->isFinalized =
            $this->isMcryptInitialized = false;
        $this->buffer = '';
    }

    /**
     * Initialize this cipher.
     *
     * @param KeyInterface $key The key to use.
     * @param string|null  $iv  The initialization vector to use, or null to generate one.
     */
    protected function doInitialize(KeyInterface $key, $iv = null)
    {
        if (null === $iv) {
            $iv = $this->randomSource()->generate(16);
        }

        $this->isInitialized = true;
        $this->key = $key;
        $this->iv = $iv;
        $this->header = $this->header($this->iv);

        $this->mcryptModule = mcrypt_module_open(
            MCRYPT_RIJNDAEL_128,
            '',
            MCRYPT_MODE_CBC,
            ''
        );
        $this->isMcryptInitialized = false;

        $this->hashContext = hash_init(
            'sha' . $key->authSecretBits(),
            HASH_HMAC,
            $key->authSecret()
        );

        $this->reset();
    }

    /**
     * Get the encryption header.
     *
     * @param string $iv The initialization vector.
     *
     * @return string The header.
     */
    abstract protected function header($iv);

    private function authenticateBlocks($output)
    {
        $authenticated = '';
        foreach (str_split($output, 16) as $block) {
            $hashContext = hash_copy($this->hashContext);
            hash_update($hashContext, $block);
            hash_update($this->finalHashContext, $block);

            $authenticated .= $block .
                substr(hash_final($hashContext, true), 0, 2);
        }

        return $authenticated;
    }

    private $randomSource;
    private $padder;
    private $resultFactory;
    private $isInitialized;
    private $isHeaderSent;
    private $isFinalized;
    private $key;
    private $iv;
    private $header;
    private $mcryptModule;
    private $isMcryptInitialized;
    private $hashContext;
    private $finalHashContext;
    private $buffer;
    private $result;
}
