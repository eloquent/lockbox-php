<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Stream\Filter;

use Eloquent\Lockbox\Cipher\CipherInterface;
use php_user_filter;

/**
 * An abstract base class for implementing cipher stream filters.
 */
abstract class AbstractCipherStreamFilter extends php_user_filter
{
    /**
     * Called upon filter creation.
     */
    public function onCreate()
    {
        $this->cipher = $this->createCipher();
        $this->cipher->initialize($this->params);

        return true;
    }

    /**
     * Filter the input data through the transform.
     *
     * @param resource $input     The input bucket brigade.
     * @param resource $output    The output bucket brigade.
     * @param integer  &$consumed The number of bytes consumed.
     * @param boolean  $isEnd     True if the stream is closing.
     *
     * @return integer The result code.
     */
    public function filter($input, $output, &$consumed, $isEnd)
    {
        $bucket = stream_bucket_make_writeable($input);
        if ($isEnd && !$bucket) {
            $bucket = stream_bucket_new(STDIN, '');
        }

        $hasOutput = false;
        while ($bucket) {
            if ($isEnd) {
                $outputBuffer = $this->cipher->finalize($bucket->data);
            } else {
                $outputBuffer = $this->cipher->process($bucket->data);
            }

            if ('' !== $outputBuffer) {
                $bucket->data = $outputBuffer;
                stream_bucket_append($output, $bucket);
                $hasOutput = true;
            }

            if (
                $this->cipher->hasResult() &&
                !$this->cipher->result()->isSuccessful()
            ) {
                return PSFS_ERR_FATAL;
            }

            $bucket = stream_bucket_make_writeable($input);
        }

        if ($hasOutput || $isEnd) {
            return PSFS_PASS_ON;
        }

        return PSFS_FEED_ME;
    }

    /**
     * Create the cipher.
     *
     * @return CipherInterface The cipher.
     */
    abstract protected function createCipher();

    private $cipher;
}
