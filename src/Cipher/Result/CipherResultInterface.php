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

/**
 * The interface implemented by cipher results.
 */
interface CipherResultInterface
{
    /**
     * Get the result type.
     *
     * @return CipherResultType The result type.
     */
    public function type();

    /**
     * Returns true if this result is successful.
     *
     * @return boolean True if successful.
     */
    public function isSuccessful();

    /**
     * Set the data.
     *
     * @param string|null $data The data, or null if unavailable.
     */
    public function setData($data);

    /**
     * Get the data.
     *
     * This method will return null for unsuccessful and/or streaming results.
     *
     * @return string|null The data, or null if unavailable.
     */
    public function data();
}
