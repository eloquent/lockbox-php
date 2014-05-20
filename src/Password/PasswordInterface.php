<?php // @codeCoverageIgnoreStart

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Password;

use Eloquent\Lockbox\Cipher\Parameters\CipherParametersInterface;

/**
 * The interface implemented by passwords.
 */
interface PasswordInterface extends CipherParametersInterface
{
    /**
     * Get the string representation of this password.
     *
     * @return string The password string.
     */
    public function string();

    /**
     * Get the string representation of this password.
     *
     * @return string The password string.
     */
    public function __toString();
}
