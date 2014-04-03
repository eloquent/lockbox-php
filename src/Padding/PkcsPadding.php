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

use Eloquent\Lockbox\Comparator\SlowStringComparator;

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
     * @return tuple<boolean,string> A 2-tuple containing a boolean true if successful, and the data, which will be unpadded if successful.
     */
    public function unpad($data)
    {
        $dataSize = strlen($data);
        $isEmpty = 0 === $dataSize;
        if ($isEmpty) {
            $data = "\0";
        }
        $padSize = ord(substr($data, $dataSize - 1, 1));
        $padIndex = $dataSize - $padSize;
        $padding = $this->slowSubString(
            $data,
            $padIndex,
            $padSize,
            $this->blockSize()
        );

        var_dump($padSize, $padIndex, $padding, $padSize, $dataSize);

        $isSuccessful = SlowStringComparator::isEqual(
            str_repeat(chr($padSize), $padSize),
            $padding
        ) && $padding;

        if ($isSuccessful) {
            $finalSize = $padIndex;
        } else {
            $finalSize = $dataSize;
        }

        return array(
            $isSuccessful,
            $this->slowSubString($data, 0, $finalSize, $this->blockSize())
        );
    }

    private function slowSubString($data, $offset, $size, $maxSize)
    {
        $result = '';
        $discard = '';

        for ($i = 0; $i < $maxSize; $i ++) {
            if ($i >= $offset && $i < $size) {
                $result .= $data[$i];
            } else {
                $discard .= $data[$i];
            }
        }

        var_dump($result, $discard);

        return $result;
    }

    private static $instance;
    private $blockSize;
}
