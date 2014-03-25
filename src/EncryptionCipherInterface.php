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
 * The interface implemented by ciphers that encrypt data.
 */
interface EncryptionCipherInterface
{
    /**
     * Encrypt a data packet.
     *
     * @param Key\KeyInterface $key  The key to encrypt with.
     * @param string           $data The data to encrypt.
     *
     * @return string The encrypted data.
     */
    public function encrypt(Key\KeyInterface $key, $data);
}
