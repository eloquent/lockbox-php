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

use Eloquent\Lockbox\Cipher\Parameters\CipherParametersInterface;
use Exception;

/**
 * The supplied parameters are not supported by the cipher.
 */
final class UnsupportedCipherParametersException extends Exception
{
    /**
     * Construct a new unsupported cipher parameters exception.
     *
     * @param CipherParametersInterface $parameters The unsupported parameters.
     * @param Exception|null            $previous   The cause, if available.
     */
    public function __construct(
        CipherParametersInterface $parameters,
        Exception $previous = null
    ) {
        $this->parameters = $parameters;

        parent::__construct(
            sprintf(
                'Unsupported cipher parameters of type %s.',
                var_export(get_class($parameters), true)
            ),
            0,
            $previous
        );
    }

    /**
     * Get the parameters.
     *
     * @return CipherParametersInterface The parameters.
     */
    public function parameters()
    {
        return $this->parameters;
    }

    private $parameters;
}
