<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Cipher\Exception;

use Eloquent\Lockbox\Cipher\CipherInterface;
use Exception;

/**
 * The cipher is already finalized.
 */
final class CipherFinalizedException extends Exception implements
    CipherStateExceptionInterface
{
    /**
     * Construct a new cipher finalized exception.
     *
     * @param CipherInterface $cipher   The cipher.
     * @param Exception|null  $previous The cause, if available.
     */
    public function __construct(
        CipherInterface $cipher,
        Exception $previous = null
    ) {
        $this->cipher = $cipher;

        parent::__construct('The cipher is already finalized.', 0, $previous);
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

    private $cipher;
}
