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

use Eloquent\Lockbox\Cipher\CipherInterface;
use Eloquent\Lockbox\Cipher\Result\CipherResultInterface;
use React\Stream\CompositeStream;
use React\Stream\ReadableStreamInterface;
use React\Stream\Util;

/**
 * A composite cipher stream that allows reading from the end of a set of piped
 * streams.
 */
class CompositePostCipherStream extends CompositeStream implements
    CipherStreamInterface
{
    /**
     * Construct a new composite post cipher stream.
     *
     * @param CipherStreamInterface   $cipherStream The cipher stream to use.
     * @param ReadableStreamInterface $readable     The final readable stream.
     */
    public function __construct(
        CipherStreamInterface $cipherStream,
        ReadableStreamInterface $readable
    ) {
        parent::__construct($readable, $cipherStream);

        Util::forwardEvents($cipherStream, $this, array('success'));
    }

    /**
     * Get the cipher.
     *
     * @return CipherInterface The cipher.
     */
    public function cipher()
    {
        return $this->writable->cipher();
    }

    /**
     * Get the result.
     *
     * @return CipherResultInterface|null The result, if available.
     */
    public function result()
    {
        return $this->writable->result();
    }
}
