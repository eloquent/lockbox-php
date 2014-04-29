<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Cipher;

/**
 * The interface implemented by ciphers.
 */
interface CipherInterface
{
    /**
     * Process the supplied input data.
     *
     * This method may be called repeatedly with additional data.
     *
     * @param string $input The data to process.
     *
     * @return string                             Any output produced.
     * @throws Exception\CipherFinalizedException If this cipher is already finalized.
     */
    public function process($input);

    /**
     * Finalize processing and return any remaining output.
     *
     * @return string                             Any output produced.
     * @throws Exception\CipherFinalizedException If this cipher is already finalized.
     */
    public function finalize();

    /**
     * Returns true if this cipher is finalized.
     *
     * @return boolean True if finalized.
     */
    public function isFinalized();

    /**
     * Returns true if this cipher has produced a result.
     *
     * @return boolean True if a result is available.
     */
    public function hasResult();

    /**
     * Returns true if this cipher has produced a result.
     *
     * @return CipherResultInterface|null The result, if available.
     */
    public function result();
}
