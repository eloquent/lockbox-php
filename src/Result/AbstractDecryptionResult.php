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
 * An abstract base class for implementing decryption results.
 */
abstract class AbstractDecryptionResult implements DecryptionResultInterface
{
    /**
     * Construct a new decryption result.
     *
     * @param DecryptionResultType $type The result type.
     * @param string|null $data The data, or null if unavailable.
     */
    public function __construct(DecryptionResultType $type, $data = null)
    {
        $this->type = $type;
        $this->data = $data;
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

    /**
     * Get the decrypted data.
     *
     * This method will return null for unsuccessful and/or streaming results.
     *
     * @return string|null The data, or null if unavailable.
     */
    public function data()
    {
        return $this->data;
    }

    private $type;
    private $isSuccessful;
    private $data;
}
