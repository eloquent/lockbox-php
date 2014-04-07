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

/**
 * Represents the result of an attempted decryption.
 */
class DecryptionResult implements DecryptionResultInterface
{
    /**
     * Construct a new decryption result.
     *
     * @param DecryptionResultType $type The result type.
     */
    public function __construct(DecryptionResultType $type)
    {
        $this->type = $type;
    }

    /**
     * Get the result type.
     *
     * @return DecryptionResultType The result type.
     */
    public function type()
    {
        return $this->type;
    }

    /**
     * Returns true if this result is successful.
     *
     * @return boolean True if successful.
     */
    public function isSuccessful()
    {
        return $this->type()->isSuccessful();
    }

    private $type;
    private $isSuccessful;
}
