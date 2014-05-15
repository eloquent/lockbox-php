<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Password\Cipher\Parameters;

use Eloquent\Lockbox\Cipher\Parameters\CipherParametersInterface;

/**
 * The interface implemented by password decrypt parameters.
 */
interface PasswordDecryptParametersInterface extends CipherParametersInterface
{
    /**
     * Get the password.
     *
     * @return string The password.
     */
    public function password();
}
