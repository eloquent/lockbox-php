<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Result;

use Eloquent\Enumeration\AbstractMultiton;

/**
 * An enumeration of possible decryption result types.
 */
final class DecryptionResultType extends AbstractMultiton
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
     * Initialize the available decryption result types.
     */
    protected static function initializeMembers()
    {
        new static('SUCCESS', true);

        new static('INSUFFICIENT_DATA', false);
        new static('INVALID_MAC', false);
        new static('UNSUPPORTED_VERSION', false);
        new static('UNSUPPORTED_TYPE', false);
        new static('INVALID_PADDING', false);
    }

    /**
     * Construct a new decryption result type.
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
