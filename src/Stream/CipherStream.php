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
use Eloquent\Lockbox\Cipher\Exception\CipherNotInitializedException;
use Evenement\EventEmitter;
use React\Stream\Util;
use React\Stream\WritableStreamInterface;

/**
 * Wraps a cipher in a stream.
 */
class CipherStream extends EventEmitter implements CipherStreamInterface
{
    /**
     * Construct a new cipher stream.
     *
     * @param CipherInterface $cipher The cipher to use.
     *
     * @throws CipherNotInitializedException If the supplied cipher is not initialized.
     */
    public function __construct(CipherInterface $cipher)
    {
        if (!$cipher->isInitialized()) {
            throw new CipherNotInitializedException;
        }

        $this->cipher = $cipher;

        $this->isClosed = $this->isPaused = $this->hasError = false;
        $this->buffer = '';
    }

    /**
     * Get the cipher.
     *
     * @return CipherInterface The cipher.
     */
    public function cipher()
    {
        return $this->cipher;
    }

    /**
     * Returns true if this stream is writable.
     *
     * @return boolean True if writable.
     */
    public function isWritable()
    {
        return !$this->isClosed;
    }

    /**
     * Returns true if this stream is readable.
     *
     * @return boolean True if readable.
     */
    public function isReadable()
    {
        return !$this->isClosed;
    }

    /**
     * Write some data to be processed.
     *
     * @param string $data The data to process.
     *
     * @return boolean True if this stream is ready for more data.
     */
    public function write($data)
    {
        if ($this->isClosed) {
            $this->emit(
                'error',
                array(new Exception\StreamClosedException, $this)
            );

            return false;
        }

        $this->buffer .= $data;

        if ($this->isPaused) {
            return false;
        }

        $output = $this->cipher->process($this->buffer);
        $this->buffer = '';

        if ('' !== $output) {
            $this->emit('data', array($output, $this));
        }

        if ($result = $this->cipher->result()) {
            if (!$result->isSuccessful()) {
                $this->hasError = true;
                $this->emit('error', array($result, $this));
            }
        }

        return !$this->hasError;
    }

    /**
     * Process and finalize any remaining buffered data.
     *
     * @param string|null $data Additional data to process before finalizing.
     */
    public function end($data = null)
    {
        if ($this->isClosed) {
            return;
        }

        $this->isClosed = true;

        if (null !== $data) {
            $this->buffer .= $data;
        }

        $output = $this->cipher->finalize($this->buffer);
        $this->buffer = '';

        if ('' !== $output) {
            $this->emit('data', array($output, $this));
        }

        if ($result = $this->cipher->result()) {
            if (!$result->isSuccessful()) {
                $this->hasError = true;
                $this->emit('error', array($result, $this));
            }
        }

        $this->doClose();
    }

    /**
     * Close this stream.
     */
    public function close()
    {
        if ($this->isClosed) {
            return;
        }

        $this->doClose();
    }

    /**
     * Pause this stream.
     */
    public function pause()
    {
        $this->isPaused = true;
    }

    /**
     * Resume this stream.
     */
    public function resume()
    {
        $this->isPaused = false;
        $this->write('');
    }

    /**
     * Pipe the output of this stream to another stream.
     *
     * @param WritableStreamInterface $destination The destination stream.
     * @param array                   $options     A set of options for the piping process.
     *
     * @return WritableStreamInterface The destination stream.
     */
    public function pipe(
        WritableStreamInterface $destination,
        array $options = array()
    ) {
        Util::pipe($this, $destination, $options);

        return $destination;
    }

    /**
     * Get the result.
     *
     * @return CipherResultInterface|null The result, if available.
     */
    public function result()
    {
        return $this->cipher()->result();
    }

    private function doClose()
    {
        $this->isClosed = true;
        $this->isPaused = false;
        $this->buffer = '';

        $this->emit('end', array($this));
        $this->emit('close', array($this));

        if (!$this->hasError) {
            $this->emit('success', array($this));
        }
    }

    private $cipher;
    private $isClosed;
    private $isPaused;
    private $hasError;
    private $buffer;
}
