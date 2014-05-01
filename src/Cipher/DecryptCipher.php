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

use Eloquent\Lockbox\Cipher\Result\CipherResult;
use Eloquent\Lockbox\Cipher\Result\CipherResultInterface;
use Eloquent\Lockbox\Cipher\Result\CipherResultType;
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
     * @param KeyInterface           $key      The key to decrypt with.
     * @param UnpadderInterface|null $unpadder The unpadder to use.
     */
    public function __construct(
        KeyInterface $key,
        UnpadderInterface $unpadder = null
    ) {
        if (null === $unpadder) {
            $unpadder = PkcsPadding::instance();
        }

        $this->key = $key;
        $this->unpadder = $unpadder;
        $this->buffer = '';
        $this->isInitialized = $this->isFinalized = false;
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

        $this->buffer .= $input;
        $size = strlen($this->buffer);

        if (!$this->initialize($size)) {
            return '';
        }
        if ($size < 36 + $this->key->authenticationSecretBytes()) {
            return '';
        }

        $size -= 18 + $this->key->authenticationSecretBytes();
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
     * @return string                             Any output produced.
     * @throws Exception\CipherFinalizedException If this cipher is already finalized.
     */
    public function finalize($input = null)
    {
        if ($this->isFinalized) {
            throw new Exception\CipherFinalizedException;
        }

        if (null !== $input) {
            $this->buffer .= $input;
        }
        $input = null;
        $size = strlen($this->buffer);

        if ($this->isInitialized) {
            $requiredSize = 18 + $this->key->authenticationSecretBytes();
            $ciphertextSize = $size - $this->key->authenticationSecretBytes();
        } else {
            $requiredSize = 36 + $this->key->authenticationSecretBytes();
            $ciphertextSize = $size - 18 -
                $this->key->authenticationSecretBytes();
        }

        if ($size < $requiredSize || 0 !== $ciphertextSize % 18) {
            $this->setResult(
                new CipherResult(CipherResultType::INVALID_SIZE())
            );

            return '';
        }
        if (!$this->isInitialized && !$this->preCheck($size)) {
            return '';
        }
        if (!$this->initialize($size)) {
            return '';
        }

        $ciphertext = substr($this->buffer, 0, $ciphertextSize);
        $mac = substr($this->buffer, $ciphertextSize);
        $this->buffer = '';

        $output = $this->decryptBlocks($ciphertext);

        if (
            !SlowStringComparator::isEqual(
                hash_final($this->hashContext, true),
                $mac
            )
        ) {
            $this->setResult(new CipherResult(CipherResultType::INVALID_MAC()));

            return '';
        }

        if (null !== $this->mcryptModule) {
            mcrypt_generic_deinit($this->mcryptModule);
            mcrypt_module_close($this->mcryptModule);
        }

        $this->key = $this->mcryptModule = $this->hashContext = null;

        list($isSuccessful, $output) = $this->unpadder()->unpad($output);
        if (!$isSuccessful) {
            $this->setResult(
                new CipherResult(CipherResultType::INVALID_PADDING())
            );

            return '';
        }

        $this->setResult(new CipherResult(CipherResultType::SUCCESS()));

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

    private function initialize(&$size)
    {
        if ($this->isInitialized) {
            return true;
        }
        if ($size < 18) {
            return false;
        }

        $this->isInitialized = true;

        if (18 === $size) {
            $header = $this->buffer;
            $this->buffer = '';
        } else {
            $header = substr($this->buffer, 0, 18);
            $this->buffer = substr($this->buffer, 18);
        }

        $size -= 18;

        if (1 !== ord($header[0])) {
            $this->setResult(
                new CipherResult(CipherResultType::UNSUPPORTED_VERSION())
            );
        } elseif (1 !== ord($header[1])) {
            $this->setResult(
                new CipherResult(CipherResultType::UNSUPPORTED_TYPE())
            );
        }

        $this->mcryptModule = mcrypt_module_open(
            MCRYPT_RIJNDAEL_128,
            '',
            MCRYPT_MODE_CBC,
            ''
        );
        mcrypt_generic_init(
            $this->mcryptModule,
            $this->key->encryptionSecret(),
            substr($header, 2, 16)
        );

        $this->hashContext = hash_init(
            'sha' . $this->key->authenticationSecretBits(),
            HASH_HMAC,
            $this->key->authenticationSecret()
        );
        hash_update($this->hashContext, $header);

        return true;
    }

    private function decryptBlocks($input)
    {
        $output = '';
        foreach (str_split($input, 18) as $block) {
            list($block, $mac) = str_split($block, 16);

            if (
                !SlowStringComparator::isEqual(
                    substr(
                        hash_hmac(
                            'sha' . $this->key->authenticationSecretBits(),
                            $block,
                            $this->key->authenticationSecret(),
                            true
                        ),
                        0,
                        2
                    ),
                    $mac
                )
            ) {
                $this->setResult(
                    new CipherResult(CipherResultType::INVALID_MAC())
                );
            }

            hash_update($this->hashContext, $block);
            $output .= mdecrypt_generic($this->mcryptModule, $block);
        }

        return $output;
    }

    private function preCheck($size)
    {
        $header = substr($this->buffer, 0, 18);
        $ciphertext = substr(
            $this->buffer,
            18,
            $size - 18 - $this->key->authenticationSecretBytes()
        );
        $mac = substr(
            $this->buffer,
            $size - $this->key->authenticationSecretBytes()
        );

        $hashContext = hash_init(
            'sha' . $this->key->authenticationSecretBits(),
            HASH_HMAC,
            $this->key->authenticationSecret()
        );
        hash_update($hashContext, $header);

        foreach (str_split($ciphertext, 18) as $block) {
            list($block) = str_split($block, 16);
            hash_update($hashContext, $block);
        }

        if (
            !SlowStringComparator::isEqual(hash_final($hashContext, true), $mac)
        ) {
            $this->setResult(new CipherResult(CipherResultType::INVALID_MAC()));

            return false;
        }

        return true;
    }

    private function setResult(CipherResultInterface $result)
    {
        if (!$this->result) {
            $this->result = $result;
        }
    }

    private $key;
    private $padder;
    private $buffer;
    private $isInitialized;
    private $isFinalized;
    private $mcryptModule;
    private $hashContext;
    private $result;
}
