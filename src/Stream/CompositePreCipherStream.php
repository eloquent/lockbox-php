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
use React\Stream\Util;
use React\Stream\WritableStreamInterface;

/**
 * A composite cipher stream that allows writing to the beginning of a set of
 * piped streams.
 */
class CompositePreCipherStream extends CompositeStream implements
    CipherStreamInterface
{
    /**
     * Construct a new composite pre cipher stream.
     *
     * @param CipherStreamInterface   $cipherStream The cipher stream to use.
     * @param WritableStreamInterface $writable     The final writable stream.
     */
    public function __construct(
        CipherStreamInterface $cipherStream,
        WritableStreamInterface $writable
    ) {
        parent::__construct($cipherStream, $writable);

        Util::forwardEvents($cipherStream, $this, array('success'));
    }

    /**
     * Get the cipher stream.
     *
     * @return CipherStreamInterface The cipher stream.
     */
    public function cipherStream()
    {
        return $this->readable;
    }

    /**
     * Get the writable stream.
     *
     * @return WritableStreamInterface The writable stream.
     */
    public function writable()
    {
        return $this->writable;
    }

    /**
     * Get the cipher.
     *
     * @return CipherInterface The cipher.
     */
    public function cipher()
    {
        return $this->cipherStream()->cipher();
    }

    /**
     * Get the result.
     *
     * @return CipherResultInterface|null The result, if available.
     */
    public function result()
    {
        return $this->cipherStream()->result();
    }
}
