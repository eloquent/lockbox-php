<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Key;

/**
 * The interface implemented by public encryption keys.
 */
interface PublicKeyInterface extends KeyInterface
{
    /**
     * Get the string representation of this key.
     *
     * @return string The string representation.
     */
    public function string();
}
