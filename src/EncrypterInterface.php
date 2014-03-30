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

use Eloquent\Endec\Transform\TransformStreamInterface;

/**
 * The interface implemented by encrypters.
 */
interface EncrypterInterface
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

    /**
     * Create a new encrypt stream.
     *
     * @param Key\KeyInterface $key The key to encrypt with.
     *
     * @return TransformStreamInterface The newly created encrypt stream.
     */
    public function createEncryptStream(Key\KeyInterface $key);
}
