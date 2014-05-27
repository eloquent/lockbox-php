<?php // @codeCoverageIgnoreStart

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Key\Deriver;

use Eloquent\Lockbox\Key\Exception\InvalidKeyParameterExceptionInterface;
use Eloquent\Lockbox\Key\KeyInterface;
use Eloquent\Lockbox\Password\PasswordInterface;

/**
 * The interface implemented by encryption key derivers.
 */
interface KeyDeriverInterface
{
    /**
     * Derive a key from a password.
     *
     * @param PasswordInterface $password    The password.
     * @param integer           $iterations  The number of hash iterations to use.
     * @param string|null       $salt        The salt to use, or null to generate a random salt.
     * @param string|null       $name        The name.
     * @param string|null       $description The description.
     *
     * @return tuple<KeyInterface,string>            A 2-tuple of the derived key, and the salt used.
     * @throws InvalidKeyParameterExceptionInterface If the supplied arguments are invalid.
     */
    public function deriveKeyFromPassword(
        PasswordInterface $password,
        $iterations,
        $salt = null,
        $name = null,
        $description = null
    );
}
