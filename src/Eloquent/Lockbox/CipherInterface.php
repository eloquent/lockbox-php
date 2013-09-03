<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Eloquent\Lockbox;

/**
 * The interface implemented by bi-directional ciphers.
 */
interface CipherInterface extends
    EncryptionCipherInterface,
    DecryptionCipherInterface
{
}
