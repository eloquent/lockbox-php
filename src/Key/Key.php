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
     * @throws Exception\InvalidKeyExceptionInterface If the key is invalid.
     */
    public function __construct(
        $encryptionSecret,
        $authenticationSecret,
        $name = null,
        $description = null
    ) {
        if (!is_string($encryptionSecret)) {
            throw new Exception\InvalidSecretException($encryptionSecret);
        }
        if (!is_string($authenticationSecret)) {
            throw new Exception\InvalidSecretException($authenticationSecret);
        }

        $encryptionSecretSize = strlen($encryptionSecret);
        switch ($encryptionSecretSize) {
            case 32:
            case 24:
            case 16:
                break;

            default:
                throw new Exception\InvalidEncryptionSecretSizeException(
                    $encryptionSecretSize * 8
                );
        }

        $authenticationSecretSize = strlen($authenticationSecret);
        switch ($authenticationSecretSize) {
            case 64:
            case 48:
            case 32:
            case 28:
                break;

            default:
                throw new Exception\InvalidAuthenticationSecretSizeException(
                    $authenticationSecretSize * 8
                );
        }

        $this->encryptionSecret = $encryptionSecret;
        $this->authenticationSecret = $authenticationSecret;
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
     * Get the authentication secret.
     *
     * @return string The authentication secret.
     */
    public function authenticationSecret()
    {
        return $this->authenticationSecret;
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

    /**
     * Get the size of the encryption secret in bits.
     *
     * @return integer The size of the encryption secret in bits.
     */
    public function encryptionSecretSize()
    {
        return strlen($this->encryptionSecret()) * 8;
    }

    /**
     * Get the size of the authentication secret in bits.
     *
     * @return integer The size of the authentication secret in bits.
     */
    public function authenticationSecretSize()
    {
        return strlen($this->authenticationSecret()) * 8;
    }

    private $encryptionSecret;
    private $authenticationSecret;
    private $name;
    private $description;
}
