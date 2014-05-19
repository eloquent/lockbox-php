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
 * The supplied secret is invalid.
 */
final class InvalidSecretException extends Exception implements
    InvalidKeyParameterExceptionInterface
{
    /**
     * Construct a new invalid secret exception.
     *
     * @param mixed          $secret The invalid secret.
     * @param Exception|null $cause  The cause, if available.
     */
    public function __construct($secret, Exception $cause = null)
    {
        $this->secret = $secret;

        parent::__construct(
            sprintf('Invalid secret %s.', var_export($secret, true)),
            0,
            $cause
        );
    }

    /**
     * Get the invalid secret.
     *
     * @return mixed The secret.
     */
    public function secret()
    {
        return $this->secret;
    }

    private $secret;
}
