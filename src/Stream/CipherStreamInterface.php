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

use Eloquent\Lockbox\Cipher\Result\CipherResultInterface;
use React\Stream\ReadableStreamInterface;
use React\Stream\WritableStreamInterface;

/**
 * The interface implemented by cipher streams.
 */
interface CipherStreamInterface extends
    ReadableStreamInterface,
    WritableStreamInterface
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
