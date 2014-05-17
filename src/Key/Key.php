<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Key;

use Eloquent\Lockbox\Key\Exception\InvalidAuthenticationSecretSizeException;
use Eloquent\Lockbox\Key\Exception\InvalidEncryptionSecretSizeException;
use Eloquent\Lockbox\Key\Exception\InvalidKeyParameterExceptionInterface;
use Eloquent\Lockbox\Key\Exception\InvalidSecretException;

/**
 * Represents an encryption key.
 */
class Key implements KeyInterface
{
    /**
     * Construct a new key.
     *
     * @param string      $encryptionSecret     The encryption secret.
     * @param string      $authenticationSecret The authentication secret.
     * @param string|null $name                 The name.
     * @param string|null $description          The description.
     *
     * @throws InvalidKeyParameterExceptionInterface If the supplied arguments are invalid.
     */
    public function __construct(
        $encryptionSecret,
        $authenticationSecret,
        $name = null,
        $description = null
    ) {
        if (!is_string($encryptionSecret)) {
            throw new InvalidSecretException($encryptionSecret);
        }
        if (!is_string($authenticationSecret)) {
            throw new InvalidSecretException($authenticationSecret);
        }

        $encryptionSecretBytes = strlen($encryptionSecret);
        $encryptionSecretBits = $encryptionSecretBytes * 8;
        switch ($encryptionSecretBytes) {
            case 32:
            case 24:
            case 16:
                break;

            default:
                throw new InvalidEncryptionSecretSizeException(
                    $encryptionSecretBits
                );
        }

        $authenticationSecretBytes = strlen($authenticationSecret);
        $authenticationSecretBits = $authenticationSecretBytes * 8;
        switch ($authenticationSecretBytes) {
            case 64:
            case 48:
            case 32:
            case 28:
                break;

            default:
                throw new InvalidAuthenticationSecretSizeException(
                    $authenticationSecretBits
                );
        }

        $this->encryptionSecret = $encryptionSecret;
        $this->encryptionSecretBytes = $encryptionSecretBytes;
        $this->encryptionSecretBits = $encryptionSecretBits;
        $this->authenticationSecret = $authenticationSecret;
        $this->authenticationSecretBytes = $authenticationSecretBytes;
        $this->authenticationSecretBits = $authenticationSecretBits;
        $this->name = $name;
        $this->description = $description;
    }

    /**
     * Get the encryption secret.
     *
     * @return string The encryption secret.
     */
    public function encryptionSecret()
    {
        return $this->encryptionSecret;
    }

    /**
     * Get the size of the encryption secret in bytes.
     *
     * @return integer The size of the encryption secret in bytes.
     */
    public function encryptionSecretBytes()
    {
        return $this->encryptionSecretBytes;
    }

    /**
     * Get the size of the encryption secret in bits.
     *
     * @return integer The size of the encryption secret in bits.
     */
    public function encryptionSecretBits()
    {
        return $this->encryptionSecretBits;
    }

    /**
     * Get the authentication secret.
     *
     * @return string The authentication secret.
     */
    public function authenticationSecret()
    {
        return $this->authenticationSecret;
    }

    /**
     * Get the size of the authentication secret in bytes.
     *
     * @return integer The size of the authentication secret in bytes.
     */
    public function authenticationSecretBytes()
    {
        return $this->authenticationSecretBytes;
    }

    /**
     * Get the size of the authentication secret in bits.
     *
     * @return integer The size of the authentication secret in bits.
     */
    public function authenticationSecretBits()
    {
        return $this->authenticationSecretBits;
    }

    /**
     * Get the name.
     *
     * @return string|null The name, or null if the key has no name.
     */
    public function name()
    {
        return $this->name;
    }

    /**
     * Get the description.
     *
     * @return string|null The description, or null if the key has no description.
     */
    public function description()
    {
        return $this->description;
    }

    private $encryptionSecret;
    private $encryptionSecretBytes;
    private $encryptionSecretBits;
    private $authenticationSecret;
    private $authenticationSecretBytes;
    private $authenticationSecretBits;
    private $name;
    private $description;
}
