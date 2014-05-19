<?php // @codeCoverageIgnoreStart

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
 * The interface implemented by encrypt parameters.
 */
interface EncryptParametersInterface extends CipherParametersInterface
{
    /**
     * Get the key.
     *
     * @return KeyInterface The key.
     */
    public function key();

    /**
     * Get the initialization vector.
     *
     * @return string|null The initialization vector, or null if none was specified.
     */
    public function iv();
}
