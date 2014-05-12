<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Stream;

use Eloquent\Confetti\TransformStream;
use Eloquent\Lockbox\Transform\CipherTransformInterface;

/**
 * A transform stream for raw decryption.
 */
class RawDecryptStream extends TransformStream implements DecryptStreamInterface
{
    /**
     * Construct a new raw decrypt stream.
     *
     * @param CipherTransformInterface $transform  The transform to use.
     * @param integer|null             $bufferSize The buffer size in bytes.
     */
    public function __construct(
        CipherTransformInterface $transform,
        $bufferSize = null
    ) {
        parent::__construct($transform, $bufferSize);
    }

    /**
     * Get the decryption result.
     *
     * @return DecryptionResultInterface|null The decryption result, or null if not yet known.
     */
    public function result()
    {
        return $this->transform()->result();
    }
}
