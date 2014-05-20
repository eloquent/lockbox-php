<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Stream\Exception;

use Exception;
use React\Stream\ReadableStreamInterface;
use React\Stream\WritableStreamInterface;

/**
 * The stream is closed.
 */
final class StreamClosedException extends Exception
{
    /**
     * Construct a new stream closed exception.
     *
     * @param ReadableStreamInterface|WritableStreamInterface $stream The stream.
     * @param Exception|null                                  $cause  The cause, if available.
     */
    public function __construct($stream, Exception $cause = null)
    {
        $this->stream = $stream;

        parent::__construct('The stream is closed.', 0, $cause);
    }

    /**
     * Get the stream.
     *
     * @return ReadableStreamInterface|WritableStreamInterface The stream.
     */
    public function stream()
    {
        return $this->stream;
    }

    private $stream;
}
