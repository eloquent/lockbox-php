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

use Eloquent\Endec\Base64\Base64Url;

/**
 * Represents an encryption key.
 */
class Key implements KeyInterface
{
    /**
     * Construct a new key.
     *
     * @param string      $data        The raw key data.
     * @param string|null $name        The name.
     * @param string|null $description The description.
     *
     * @throws Exception\InvalidKeyExceptionInterface If the key is invalid.
     */
    public function __construct($data, $name = null, $description = null)
    {
        if (!is_string($data)) {
            throw new Exception\InvalidKeyException($data);
        }

        $size = strlen($data);
        switch ($size) {
            case 32:
            case 24:
            case 16:
                break;

            default:
                throw new Exception\InvalidKeySizeException($size * 8);
        }

        $this->data = $data;
        $this->name = $name;
        $this->description = $description;
    }

    /**
     * Get the raw key data.
     *
     * @return string The raw key data.
     */
    public function data()
    {
        return $this->data;
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
     * Get the size of the key in bits.
     *
     * @return integer The size of the key in bits.
     */
    public function size()
    {
        return strlen($this->data()) * 8;
    }

    /**
     * Get the string representation of this key.
     *
     * @return string The string representation.
     */
    public function string()
    {
        return Base64Url::instance()->encode($this->data());
    }

    /**
     * Get the string representation of this key.
     *
     * @return string The string representation.
     */
    public function __toString()
    {
        return $this->string();
    }

    private $data;
    private $name;
    private $description;
}
