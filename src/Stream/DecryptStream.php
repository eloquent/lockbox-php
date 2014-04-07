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

use Eloquent\Confetti\CompoundTransformInterface;
use Eloquent\Confetti\TransformStream;

/**
 * A transform stream for encoded decryption.
 */
class DecryptStream extends TransformStream implements DecryptStreamInterface
{
    /**
     * Construct a new decrypt stream.
     *
     * @param CompoundTransformInterface $transform  The transform to use.
     * @param integer|null               $bufferSize The buffer size in bytes.
     */
    public function __construct(
        CompoundTransformInterface $transform,
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
        $transforms = $this->transform()->transforms();

        return $transforms[1]->result();
    }
}
