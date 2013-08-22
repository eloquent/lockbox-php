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
 * The interface implemented by ciphers that decrypt data.
 */
interface DecryptionCipherInterface
{
    /**
     * Decrypt a data packet,
     *
     * @param Key\PrivateKeyInterface $key  The key to decrypt with.
     * @param string                  $data The data to decrypt.
     *
     * @return string                              The decrypted data.
     * @throws Exception\DecryptionFailedException If the decryption failed.
     */
    public function decrypt(Key\PrivateKeyInterface $key, $data);
}
