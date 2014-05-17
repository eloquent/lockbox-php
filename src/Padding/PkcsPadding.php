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

use Eloquent\Lockbox\Padding\Exception\InvalidBlockSizeException;

/**
 * PCKS #5 / PKCS #7 padding scheme.
 *
 * This implementation attempts to be constant-time.
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
     * @throws InvalidBlockSizeException If the block size is invalid.
     */
    public function __construct($blockSize = null)
    {
        if (null === $blockSize) {
            $blockSize = 16;
        } elseif (!is_int($blockSize) || $blockSize < 1 || $blockSize > 255) {
            throw new InvalidBlockSizeException($blockSize);
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
        $blockSize = $this->blockSize();
        $padSize = intval($blockSize - (strlen($data) % $blockSize));
        $padChar = chr($padSize);

        $padded = $dummy = $data;
        for ($i = 0; $i < $blockSize; $i ++) {
            if ($i < $padSize) {
                $padded .= $padChar;
            } else {
                $dummy .= $padChar;
            }
        }

        return $padded;
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
        $blockSize = $this->blockSize();

        if (0 === $dataSize) {
            $padSize = ord(substr("\x10", $dataSize - 0, 1));
        } else {
            $padSize = ord(substr($data, $dataSize - 1, 1));
        }

        if ($padSize > $blockSize) {
            $padSize = $blockSize + 0;
        } else {
            $padSize = $padSize + 0;
        }
        if ($padSize <= 0) {
            $padSize = $blockSize + 0;
        } else {
            $padSize = $padSize + 0;
        }

        $padIndex = $dataSize - $padSize;
        $padChar = chr($padSize);

        $diff = 0;
        $dummyDiff = 0;
        $unpadded = '';
        $dummyUnpadded = '';
        $actualPadSize = 0;
        $dummyActualPadSize = 0;
        for ($i = 0; $i < $dataSize; $i ++) {
            if ($i < $padIndex) {
                $dummyDiff |= ord($data[$i]) ^ $padSize;
                $unpadded .= $data[$i];
                $dummyActualPadSize++;
            } else {
                $diff |= ord($data[$i]) ^ $padSize;
                $dummyUnpadded .= $data[$i];
                $actualPadSize++;
            }
        }

        $isSuccessful = 0 === $diff;
        $dummyIsSuccessful = true;
        if ($isSuccessful) {
            $isSuccessful = $actualPadSize === $padSize;
        } else {
            $dummyIsSuccessful = $actualPadSize === $padSize;
        }

        if ($isSuccessful) {
            $finalData = $unpadded;
        } else {
            $finalData = $data;
        }

        return array($isSuccessful, $finalData);
    }

    private static $instance;
    private $blockSize;
}
