<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Cipher\Result;

use Eloquent\Enumeration\AbstractMultiton;

/**
 * An enumeration of possible cipher result types.
 */
final class CipherResultType extends AbstractMultiton
{
    /**
     * Returns true if this result type indicates a successful result.
     *
     * @return boolean True if successful.
     */
    public function isSuccessful()
    {
        return $this->isSuccessful;
    }

    /**
     * Initialize the available cipher result types.
     */
    protected static function initializeMembers()
    {
        new static('SUCCESS', true);              // Indicates a successful result.

        new static('INVALID_SIZE', false);        // The input data was an invalid size and could not be processed.
        new static('INVALID_ENCODING', false);    // The input data was not encoded, or the encoding was invalid.
        new static('INVALID_MAC', false);         // One or more message authentication codes were invalid.
        new static('UNSUPPORTED_VERSION', false); // An unsupported version identifier was encountered.
        new static('UNSUPPORTED_TYPE', false);    // An unsupported type identifier was encountered.
        new static('INVALID_PADDING', false);     // The input data was not correctly padded.
        new static('TOO_MANY_ITERATIONS', false); // The requested number of hash iterations exceeded the configured limit.
    }

    /**
     * Construct a new cipher result type.
     *
     * @param string  $key          The result key.
     * @param boolean $isSuccessful True if this result type indicates a successful result.
     */
    protected function __construct($key, $isSuccessful)
    {
        parent::__construct($key);

        $this->isSuccessful = $isSuccessful;
    }

    private $isSuccessful;
}
