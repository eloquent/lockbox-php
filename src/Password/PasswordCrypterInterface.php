<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Password;

/**
 * The interface implemented by password crypters.
 */
interface PasswordCrypterInterface extends
    PasswordEncrypterInterface,
    PasswordDecrypterInterface
{
}
