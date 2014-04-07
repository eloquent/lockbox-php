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

use Eloquent\Confetti\TransformStreamInterface;
use Eloquent\Lockbox\Result\DecryptionResultInterface;

/**
 * The interface implemented by decrypt streams.
 */
interface DecryptStreamInterface extends TransformStreamInterface
{
    /**
     * Get the decryption result.
     *
     * @return DecryptionResultInterface|null The decryption result, or null if not yet known.
     */
    public function result();
}
