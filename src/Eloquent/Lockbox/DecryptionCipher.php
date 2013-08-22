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
 * The standard Lockbox decryption cipher.
 */
class DecryptionCipher implements DecryptionCipherInterface
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
    public function decrypt(Key\PrivateKeyInterface $key, $data)
    {
        $data = base64_decode($data);
        if (false === $data) {
            throw new Exception\DecryptionFailedException;
        }

        $envelope = substr($data, 0, $key->envelopeSize());
        $data = substr($data, $key->envelopeSize());

        if (
            !openssl_open(
                $data,
                $decrypted,
                $envelope,
                $key->handle()
            )
        ) {
            throw new Exception\DecryptionFailedException;
        }

        $hash = substr($decrypted, 0, 20);
        $decrypted = substr($decrypted, 20);
        if (false === $decrypted) {
            $decrypted = '';
        }

        if (sha1($decrypted, true) !== $hash) {
            throw new Exception\DecryptionFailedException;
        }

        return $decrypted;
    }
}
