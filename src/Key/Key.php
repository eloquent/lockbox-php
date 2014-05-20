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

use Eloquent\Lockbox\Key\Exception\InvalidAuthSecretSizeException;
use Eloquent\Lockbox\Key\Exception\InvalidEncryptSecretSizeException;
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
     * @param string      $encryptSecret The encrypt secret.
     * @param string      $authSecret    The auth secret.
     * @param string|null $name          The name.
     * @param string|null $description   The description.
     *
     * @throws InvalidKeyParameterExceptionInterface If the supplied arguments are invalid.
     */
    public function __construct(
        $encryptSecret,
        $authSecret,
        $name = null,
        $description = null
    ) {
        if (!is_string($encryptSecret)) {
            throw new InvalidSecretException($encryptSecret);
        }
        if (!is_string($authSecret)) {
            throw new InvalidSecretException($authSecret);
        }

        $encryptSecretBytes = strlen($encryptSecret);
        $encryptSecretBits = $encryptSecretBytes * 8;
        switch ($encryptSecretBytes) {
            case 32:
            case 24:
            case 16:
                break;

            default:
                throw new InvalidEncryptSecretSizeException($encryptSecretBits);
        }

        $authSecretBytes = strlen($authSecret);
        $authSecretBits = $authSecretBytes * 8;
        switch ($authSecretBytes) {
            case 64:
            case 48:
            case 32:
            case 28:
                break;

            default:
                throw new InvalidAuthSecretSizeException($authSecretBits);
        }

        $this->encryptSecret = $encryptSecret;
        $this->encryptSecretBytes = $encryptSecretBytes;
        $this->encryptSecretBits = $encryptSecretBits;
        $this->authSecret = $authSecret;
        $this->authSecretBytes = $authSecretBytes;
        $this->authSecretBits = $authSecretBits;
        $this->name = $name;
        $this->description = $description;
    }

    /**
     * Get the encrypt secret.
     *
     * @return string The encrypt secret.
     */
    public function encryptSecret()
    {
        return $this->encryptSecret;
    }

    /**
     * Get the size of the encrypt secret in bytes.
     *
     * @return integer The size of the encrypt secret in bytes.
     */
    public function encryptSecretBytes()
    {
        return $this->encryptSecretBytes;
    }

    /**
     * Get the size of the encrypt secret in bits.
     *
     * @return integer The size of the encrypt secret in bits.
     */
    public function encryptSecretBits()
    {
        return $this->encryptSecretBits;
    }

    /**
     * Get the auth secret.
     *
     * @return string The auth secret.
     */
    public function authSecret()
    {
        return $this->authSecret;
    }

    /**
     * Get the size of the auth secret in bytes.
     *
     * @return integer The size of the auth secret in bytes.
     */
    public function authSecretBytes()
    {
        return $this->authSecretBytes;
    }

    /**
     * Get the size of the auth secret in bits.
     *
     * @return integer The size of the auth secret in bits.
     */
    public function authSecretBits()
    {
        return $this->authSecretBits;
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

    private $encryptSecret;
    private $encryptSecretBytes;
    private $encryptSecretBits;
    private $authSecret;
    private $authSecretBytes;
    private $authSecretBits;
    private $name;
    private $description;
}
