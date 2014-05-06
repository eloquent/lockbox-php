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
use Eloquent\Lockbox\Cipher\Result\CipherResultInterface;
use Eloquent\Lockbox\Cipher\Result\CipherResultType;
use Eloquent\Lockbox\Comparator\SlowStringComparator;
use Eloquent\Lockbox\Key\KeyDeriver;
use Eloquent\Lockbox\Key\KeyDeriverInterface;
use Eloquent\Lockbox\Padding\PkcsPadding;
use Eloquent\Lockbox\Padding\UnpadderInterface;
use Eloquent\Lockbox\Password\Cipher\Result\PasswordDecryptionResult;

/**
 * Decrypts data with a password.
 */
class PasswordDecryptCipher implements CipherInterface
{
    /**
     * Construct a new password decrypt cipher.
     *
     * @param string                   $password   The password to decrypt with.
     * @param KeyDeriverInterface|null $keyDeriver The key deriver to use.
     * @param UnpadderInterface|null   $unpadder   The unpadder to use.
     */
    public function __construct(
        $password,
        KeyDeriverInterface $keyDeriver = null,
        UnpadderInterface $unpadder = null
    ) {
        if (null === $keyDeriver) {
            $keyDeriver = KeyDeriver::instance();
        }
        if (null === $unpadder) {
            $unpadder = PkcsPadding::instance();
        }

        $this->password = $password;
        $this->keyDeriver = $keyDeriver;
        $this->unpadder = $unpadder;
        $this->buffer = '';
        $this->isInitialized = $this->isFinalized = false;
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
        if ($size < 68) {
            return '';
        }

        $size -= 50;
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
            $requiredSize = 50;
            $ciphertextSize = $size - 32;
        } else {
            $requiredSize = 136;
            $ciphertextSize = $size - 118;
        }

        if ($size < $requiredSize || 0 !== $ciphertextSize % 18) {
            $this->setResult(
                new PasswordDecryptionResult(CipherResultType::INVALID_SIZE())
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
            $this->setResult(
                new PasswordDecryptionResult(CipherResultType::INVALID_MAC())
            );

            return '';
        }

        if (null !== $this->mcryptModule) {
            mcrypt_generic_deinit($this->mcryptModule);
            mcrypt_module_close($this->mcryptModule);
        }

        $this->password = $this->key = $this->mcryptModule =
            $this->hashContext = null;

        list($isSuccessful, $output) = $this->unpadder()->unpad($output);
        if (!$isSuccessful) {
            $this->setResult(
                new PasswordDecryptionResult(
                    CipherResultType::INVALID_PADDING()
                )
            );

            return '';
        }

        $this->setResult(
            new PasswordDecryptionResult(
                CipherResultType::SUCCESS(),
                $this->iterations
            )
        );

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
        if ($size < 86) {
            return false;
        }

        $this->isInitialized = true;

        if (86 === $size) {
            $header = $this->buffer;
            $this->buffer = '';
        } else {
            $header = substr($this->buffer, 0, 86);
            $this->buffer = substr($this->buffer, 86);
        }

        $size -= 86;

        if (1 !== ord($header[0])) {
            $this->setResult(
                new PasswordDecryptionResult(
                    CipherResultType::UNSUPPORTED_VERSION()
                )
            );
        } elseif (2 !== ord($header[1])) {
            $this->setResult(
                new PasswordDecryptionResult(
                    CipherResultType::UNSUPPORTED_TYPE()
                )
            );
        }

        list(, $this->iterations) = unpack('N', substr($header, 2, 4));
        list($this->key) = $this->keyDeriver()->deriveKeyFromPassword(
            $this->password,
            $this->iterations,
            substr($header, 6, 64)
        );
        $this->password = null;

        $this->mcryptModule = mcrypt_module_open(
            MCRYPT_RIJNDAEL_128,
            '',
            MCRYPT_MODE_CBC,
            ''
        );
        mcrypt_generic_init(
            $this->mcryptModule,
            $this->key->encryptionSecret(),
            substr($header, 70, 16)
        );

        $this->hashContext = hash_init(
            'sha256',
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
                            'sha256',
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
                    new PasswordDecryptionResult(
                        CipherResultType::INVALID_MAC()
                    )
                );
            }

            hash_update($this->hashContext, $block);
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
        list($key) = $this->keyDeriver()->deriveKeyFromPassword(
            $this->password,
            $iterations,
            substr($header, 6, 64)
        );

        $hashContext = hash_init(
            'sha256',
            HASH_HMAC,
            $key->authenticationSecret()
        );
        hash_update($hashContext, $header);

        foreach (str_split($ciphertext, 18) as $block) {
            list($block) = str_split($block, 16);
            hash_update($hashContext, $block);
        }

        if (
            !SlowStringComparator::isEqual(hash_final($hashContext, true), $mac)
        ) {
            $this->setResult(
                new PasswordDecryptionResult(
                    CipherResultType::INVALID_MAC()
                )
            );

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

    private $password;
    private $keyDeriver;
    private $padder;
    private $key;
    private $iterations;
    private $buffer;
    private $isInitialized;
    private $isFinalized;
    private $mcryptModule;
    private $hashContext;
    private $result;
}
