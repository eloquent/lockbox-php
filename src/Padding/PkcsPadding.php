<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Padding;

/**
 * PCKS #5 / PKCS #7 padding scheme.
 *
 * @link http://tools.ietf.org/html/rfc2315#section-10.3
 */
class PkcsPadding implements PaddingSchemeInterface
{
    /**
     * Get the static instance of this padding scheme.
     *
     * @return PaddingSchemeInterface The static padding scheme.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new PKCS padding scheme.
     *
     * @param integer|null $blockSize The block size to pad to in bytes.
     *
     * @throws Exception\InvalidBlockSizeException If the block size is invalid.
     */
    public function __construct($blockSize = null)
    {
        if (null === $blockSize) {
            $blockSize = 16;
        } elseif (!is_int($blockSize) || $blockSize < 1 || $blockSize > 255) {
            throw new Exception\InvalidBlockSizeException($blockSize);
        }

        $this->blockSize = $blockSize;
    }

    /**
     * Get the block size.
     *
     * @return integer The block size in bytes.
     */
    public function blockSize()
    {
        return $this->blockSize;
    }

    /**
     * Pad a data packet to a specific block size.
     *
     * @param string $data The data to pad.
     *
     * @return string The padded data.
     */
    public function pad($data)
    {
        $padSize = intval(
            $this->blockSize() - (strlen($data) % $this->blockSize())
        );

        return $data . str_repeat(chr($padSize), $padSize);
    }

    /**
     * Remove padding from the supplied data.
     *
     * @param string $data The padded data.
     *
     * @return string                            The unpadded data.
     * @throws Exception\InvalidPaddingException If the padding is invalid.
     */
    public function unpad($data)
    {
        $padSize = ord(substr($data, -1));
        $padding = substr($data, -$padSize);

        if (str_repeat(chr($padSize), $padSize) !== $padding) {
            throw new Exception\InvalidPaddingException;
        }

        return substr($data, 0, -$padSize);
    }

    private static $instance;
    private $blockSize;
}
