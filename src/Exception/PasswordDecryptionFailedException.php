<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Exception;

use Eloquent\Endec\Transform\Exception\TransformExceptionInterface;
use Exception;

/**
 * Password decryption failed.
 */
final class PasswordDecryptionFailedException extends Exception implements
    TransformExceptionInterface
{
    /**
     * Construct a new password decryption failed exception.
     *
     * @param string         $password The password used to attempt decryption.
     * @param Exception|null $previous The cause, if available.
     */
    public function __construct($password, Exception $previous = null)
    {
        $this->password = $password;

        parent::__construct('Password decryption failed.', 0, $previous);
    }

    /**
     * Get the password used to attempt decryption.
     *
     * @return string The password.
     */
    public function password()
    {
        return $this->password;
    }

    private $password;
}
