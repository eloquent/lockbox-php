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
 * The standard Lockbox encryption cipher.
 */
class EncryptionCipher implements EncryptionCipherInterface
{
    /**
     * Encrypt a data packet.
     *
     * @param Key\PublicKeyInterface $key  The key to encrypt with.
     * @param string                 $data The data to encrypt.
     *
     * @return string                              The encrypted data.
     * @throws Exception\EncryptionFailedException If the encryption failed.
     */
    public function encrypt(Key\PublicKeyInterface $key, $data)
    {
        $result = openssl_seal(
            sha1($data, true) . $data,
            $encrypted,
            $envelopes,
            array($key->handle())
        );
        if (false === $result) {
            throw new Exception\EncryptionFailedException;
        }

        return base64_encode($envelopes[0] . $encrypted);
    }
}
