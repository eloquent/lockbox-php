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
use Eloquent\Lockbox\Cipher\Result\CipherResult;
use Eloquent\Lockbox\Cipher\Result\CipherResultInterface;
use Eloquent\Lockbox\Cipher\Result\CipherResultType;
use Eloquent\Lockbox\Key\KeyDeriver;
use Eloquent\Lockbox\Key\KeyDeriverInterface;
use Eloquent\Lockbox\Padding\PadderInterface;
use Eloquent\Lockbox\Padding\PkcsPadding;

/**
 * Encrypts data with a password.
 */
class PasswordEncryptCipher implements CipherInterface
{
    /**
     * Construct a new password encrypt data transform.
     *
     * @param string                   $password   The password to encrypt with.
     * @param integer                  $iterations The number of hash iterations to use.
     * @param string                   $salt       The salt to use for key derivation.
     * @param string                   $iv         The initialization vector to use.
     * @param KeyDeriverInterface|null $keyDeriver The key deriver to use.
     * @param PadderInterface|null     $padder     The padder to use.
     */
    public function __construct(
        $password,
        $iterations,
        $salt,
        $iv,
        KeyDeriverInterface $keyDeriver = null,
        PadderInterface $padder = null
    ) {
        if (null === $keyDeriver) {
            $keyDeriver = KeyDeriver::instance();
        }
        if (null === $padder) {
            $padder = PkcsPadding::instance();
        }

        $this->password = $password;
        $this->iterations = $iterations;
        $this->salt = $salt;
        $this->iv = $iv;
        $this->keyDeriver = $keyDeriver;
        $this->padder = $padder;
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
     * @return string                   Any output produced.
     * @throws CipherFinalizedException If this cipher is already finalized.
     */
    public function process($input)
    {
        if ($this->isFinalized) {
            throw new CipherFinalizedException;
        }

        $output = $this->initialize();

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
     * @return string                   Any output produced.
     * @throws CipherFinalizedException If this cipher is already finalized.
     */
    public function finalize($input = null)
    {
        if ($this->isFinalized) {
            throw new CipherFinalizedException;
        }

        $this->isFinalized = true;

        if (null !== $input) {
            $this->buffer .= $input;
        }
        $input = null;

        $output = $this->initialize() .
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
     * Returns true if this cipher has produced a result.
     *
     * @return CipherResultInterface|null The result, if available.
     */
    public function result()
    {
        return $this->result;
    }

    private function initialize()
    {
        if ($this->isInitialized) {
            return '';
        }

        $this->isInitialized = true;

        list($this->key) = $this->keyDeriver()->deriveKeyFromPassword(
            $this->password,
            $this->iterations,
            $this->salt
        );

        $this->mcryptModule = mcrypt_module_open(
            MCRYPT_RIJNDAEL_128,
            '',
            MCRYPT_MODE_CBC,
            ''
        );
        mcrypt_generic_init(
            $this->mcryptModule,
            $this->key->encryptionSecret(),
            $this->iv
        );

        $this->hashContext = hash_init(
            'sha' . $this->key->authenticationSecretBits(),
            HASH_HMAC,
            $this->key->authenticationSecret()
        );

        $header = chr(1) . chr(2) . pack('N', $this->iterations) . $this->salt .
            $this->iv;
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
                        'sha' . $this->key->authenticationSecretBits(),
                        $block,
                        $this->key->authenticationSecret(),
                        true
                    ),
                    0,
                    2
                );
        }

        return $authenticated;
    }

    private $password;
    private $iterations;
    private $key;
    private $iv;
    private $salt;
    private $keyDeriver;
    private $padder;
    private $buffer;
    private $isInitialized;
    private $isFinalized;
    private $mcryptModule;
    private $hashContext;
    private $result;
}
