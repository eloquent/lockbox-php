<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox;

use Eloquent\Lockbox\Cipher\Result\CipherResultInterface;
use Eloquent\Lockbox\Stream\CipherStreamInterface;

/**
 * The interface implemented by decrypters.
 */
interface DecrypterInterface
{
    /**
     * Decrypt a data packet.
     *
     * @param Key\KeyInterface $key  The key to decrypt with.
     * @param string           $data The data to decrypt.
     *
     * @return CipherResultInterface The decryption result.
     */
    public function decrypt(Key\KeyInterface $key, $data);

    /**
     * Create a new decrypt stream.
     *
     * @param Key\KeyInterface $key The key to decrypt with.
     *
     * @return CipherStreamInterface The newly created decrypt stream.
     */
    public function createDecryptStream(Key\KeyInterface $key);
}
