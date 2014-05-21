<?php // @codeCoverageIgnoreStart

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Cipher;

use Eloquent\Lockbox\Cipher\Exception\CipherStateExceptionInterface;
use Eloquent\Lockbox\Cipher\Exception\UnsupportedCipherParametersException;
use Eloquent\Lockbox\Cipher\Parameters\CipherParametersInterface;
use Eloquent\Lockbox\Cipher\Result\CipherResultInterface;

/**
 * The interface implemented by ciphers.
 */
interface CipherInterface
{
    /**
     * Returns true if this cipher is initialized.
     *
     * @return boolean True if initialized.
     */
    public function isInitialized();

    /**
     * Initialize this cipher.
     *
     * @param CipherParametersInterface $parameters The parameters to use.
     *
     * @throws UnsupportedCipherParametersException If unsupported parameters are supplied.
     */
    public function initialize(CipherParametersInterface $parameters);

    /**
     * Process the supplied input data.
     *
     * This method may be called repeatedly with additional data.
     *
     * @param string $input The data to process.
     *
     * @return string                        Any output produced.
     * @throws CipherStateExceptionInterface If the cipher is in an invalid state.
     */
    public function process($input);

    /**
     * Finalize processing and return any remaining output.
     *
     * @param string|null $input Any remaining data to process.
     *
     * @return string                        Any output produced.
     * @throws CipherStateExceptionInterface If the cipher is in an invalid state.
     */
    public function finalize($input = null);

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
     * Get the result.
     *
     * @return CipherResultInterface|null The result, if available.
     */
    public function result();

    /**
     * Reset this cipher to the state just after the last initialize() call.
     */
    public function reset();

    /**
     * Reset this cipher to its initial state, and clear any sensitive data.
     */
    public function deinitialize();
}
