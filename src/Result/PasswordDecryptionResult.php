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
 * The interface implemented by password decryption results.
 */
class PasswordDecryptionResult extends AbstractDecryptionResult implements
    PasswordDecryptionResultInterface
{
    /**
     * Construct a new password decryption result.
     *
     * @param DecryptionResultType $type       The result type.
     * @param string|null          $data       The data, or null if unavailable.
     * @param integer|null         $iterations The hash iterations, or null if unsuccessful.
     */
    public function __construct(
        DecryptionResultType $type,
        $data = null,
        $iterations = null
    ) {
        parent::__construct($type, $data);

        $this->iterations = $iterations;
    }

    /**
     * Get the number of hash iterations used.
     *
     * @return integer|null The hash iterations, or null if unsuccessful.
     */
    public function iterations()
    {
        return $this->iterations;
    }

    private $iterations;
}
