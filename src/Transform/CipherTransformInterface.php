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
use Eloquent\Lockbox\Cipher\CipherInterface;
use Eloquent\Lockbox\Cipher\Result\CipherResultInterface;

/**
 * The interface implemented by cipher transforms.
 */
interface CipherTransformInterface extends TransformInterface
{
    /**
     * Get the cipher.
     *
     * @return CipherInterface The cipher.
     */
    public function cipher();

    /**
     * Get the result.
     *
     * @return CipherResultInterface|null The result, if available.
     */
    public function result();
}
