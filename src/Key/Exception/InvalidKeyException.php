<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Key\Exception;

use Exception;

/**
 * The supplied key is invalid.
 */
final class InvalidKeyException extends Exception implements
    InvalidKeyExceptionInterface
{
    /**
     * Construct a new invalid key exception.
     *
     * @param mixed          $key      The invalid key.
     * @param Exception|null $previous The cause, if available.
     */
    public function __construct($key, Exception $previous = null)
    {
        $this->key = $key;

        parent::__construct(
            sprintf('Invalid key %s.', var_export($key, true)),
            0,
            $previous
        );
    }

    /**
     * Get the invalid key.
     *
     * @return mixed The key.
     */
    public function key()
    {
        return $this->key;
    }

    private $key;
}
