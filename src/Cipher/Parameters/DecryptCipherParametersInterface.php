<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Cipher\Parameters;

use Eloquent\Lockbox\Key\KeyInterface;

/**
 * The interface implemented by decrypt cipher parameters.
 */
interface DecryptCipherParametersInterface extends CipherParametersInterface
{
    /**
     * Get the key.
     *
     * @return KeyInterface The key.
     */
    public function key();
}
