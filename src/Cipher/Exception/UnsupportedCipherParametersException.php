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
     * @param CipherInterface           $cipher     The cipher.
     * @param CipherParametersInterface $parameters The unsupported parameters.
     * @param Exception|null            $previous   The cause, if available.
     */
    public function __construct(
        CipherInterface $cipher,
        CipherParametersInterface $parameters,
        Exception $previous = null
    ) {
        $this->cipher = $cipher;
        $this->parameters = $parameters;

        parent::__construct(
            sprintf(
                'Cipher of type %s does not support parameters of type %s.',
                var_export(get_class($cipher), true),
                var_export(get_class($parameters), true)
            ),
            0,
            $previous
        );
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

    /**
     * Get the parameters.
     *
     * @return CipherParametersInterface The parameters.
     */
    public function parameters()
    {
        return $this->parameters;
    }

    private $cipher;
    private $parameters;
}
