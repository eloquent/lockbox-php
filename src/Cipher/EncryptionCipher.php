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

use Eloquent\Lockbox\Key\KeyInterface;
use Eloquent\Lockbox\Padding\PadderInterface;
use Eloquent\Lockbox\Padding\PkcsPadding;

/**
 * Encrypts data with a key.
 */
class EncryptionCipher implements CipherInterface
{
    /**
     * Construct a new encryption cipher.
     *
     * @param KeyInterface         $key    The key to encrypt with.
     * @param string               $iv     The initialization vector to use.
     * @param PadderInterface|null $padder The padder to use.
     */
    public function __construct(
        KeyInterface $key,
        $iv,
        PadderInterface $padder = null
    ) {
        if (null === $padder) {
            $padder = PkcsPadding::instance();
        }

        $this->iv = $iv;
        $this->padder = $padder;
        $this->buffer = '';
        $this->isHeaderSent = $this->isFinalized = false;

        $this->mcryptModule = mcrypt_module_open(
            MCRYPT_RIJNDAEL_128,
            '',
            MCRYPT_MODE_CBC,
            ''
        );
        mcrypt_generic_init(
            $this->mcryptModule,
            $key->encryptionSecret(),
            $iv
        );

        $this->hashAlgorithm = 'sha' . $key->authenticationSecretBits();
        $this->authenticationSecret = $key->authenticationSecret();
        $this->hashContext = hash_init(
            $this->hashAlgorithm,
            HASH_HMAC,
            $this->authenticationSecret
        );
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
     * Process the supplied input data.
     *
     * This method may be called repeatedly with additional data.
     *
     * @param string $input The data to process.
     *
     * @return string                             Any output produced.
     * @throws Exception\CipherFinalizedException If this cipher is already finalized.
     */
    public function process($input)
    {
        if ($this->isFinalized) {
            throw new Exception\CipherFinalizedException;
        }

        $output = $this->handleHeader();

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
     * @return string                             Any output produced.
     * @throws Exception\CipherFinalizedException If this cipher is already finalized.
     */
    public function finalize()
    {
        if ($this->isFinalized) {
            throw new Exception\CipherFinalizedException;
        }

        $output = $this->handleHeader() .
            $this->authenticateBlocks(
                mcrypt_generic(
                    $this->mcryptModule,
                    $this->padder->pad($this->buffer)
                )
            ) .
            hash_final($this->hashContext, true);

        $this->buffer = $this->authenticationSecret = $this->iv = null;
        mcrypt_generic_deinit($this->mcryptModule);
        mcrypt_module_close($this->mcryptModule);

        $this->isFinalized = true;
        $this->result = CipherResult::SUCCESS();

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
     * Returns true if this cipher has produced a result.
     *
     * @return CipherResultInterface|null The result, if available.
     */
    public function result()
    {
        return $this->result;
    }

    private function handleHeader()
    {
        if ($this->isHeaderSent) {
            return '';
        }

        $this->isHeaderSent = true;
        $header = chr(1) . chr(1) . $this->iv;
        hash_update($this->hashContext, $header);

        return $header;
    }

    private function authenticateBlocks($output)
    {
        $authenticated = '';
        foreach (str_split($output, 16) as $block) {
            hash_update($this->hashContext, $block);

            $authenticated .=
                $block .
                substr(
                    hash_hmac(
                        $this->hashAlgorithm,
                        $block,
                        $this->authenticationSecret,
                        true
                    ),
                    0,
                    2
                );
        }

        return $authenticated;
    }

    private $padder;
    private $buffer;
    private $mcryptModule;
    private $hashAlgorithm;
    private $authenticationSecret;
    private $hashContext;
    private $iv;
    private $isHeaderSent;
    private $isFinalized;
    private $result;
}
