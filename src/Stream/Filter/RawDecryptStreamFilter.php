<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Stream\Filter;

use Eloquent\Lockbox\Cipher\DecryptCipher;

/**
 * A stream filter for raw decryption with a key.
 */
class RawDecryptStreamFilter extends AbstractCipherStreamFilter
{
    /**
     * Create the cipher.
     *
     * @return CipherInterface The cipher.
     */
    protected function createCipher()
    {
        return new DecryptCipher;
    }
}
