<?php // @codeCoverageIgnoreStart

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Transform;

use Eloquent\Confetti\TransformInterface;
use Eloquent\Lockbox\Cipher\Result\CipherResultInterface;

/**
 * The interface implemented by decrypt transforms.
 */
interface DecryptTransformInterface extends TransformInterface
{
    /**
     * Get the decryption result.
     *
     * @return CipherResultInterface|null The decryption result, or null if not yet known.
     */
    public function result();
}
