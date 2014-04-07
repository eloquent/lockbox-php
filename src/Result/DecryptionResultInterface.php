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
 * The interface implemented by decryption results.
 */
interface DecryptionResultInterface
{
    /**
     * Get the result type.
     *
     * @return DecryptionResultType The result type.
     */
    public function type();

    /**
     * Returns true if this result is successful.
     *
     * @return boolean True if successful.
     */
    public function isSuccessful();
}
