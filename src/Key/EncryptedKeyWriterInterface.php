<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Key;

/**
 * The interface implemented by encrypted key writers.
 */
interface EncryptedKeyWriterInterface extends KeyWriterInterface
{
    /**
     * Write a key, encrypted with a password, to the supplied path.
     *
     * @param string       $password   The password.
     * @param integer      $iterations The number of hash iterations to use.
     * @param KeyInterface $key        The key.
     * @param string       $path       The path to write to.
     *
     * @throws Exception\KeyWriteException If the key cannot be written.
     */
    public function writeFileWithPassword(
        $password,
        $iterations,
        KeyInterface $key,
        $path
    );

    /**
     * Write a key, encrypted with a password, to the supplied stream.
     *
     * @param string       $password   The password.
     * @param integer      $iterations The number of hash iterations to use.
     * @param KeyInterface $key        The key.
     * @param stream       $stream     The stream to write to.
     * @param string|null  $path       The path, if known.
     *
     * @throws Exception\KeyWriteException If the key cannot be written.
     */
    public function writeStreamWithPassword(
        $password,
        $iterations,
        KeyInterface $key,
        $stream,
        $path = null
    );

    /**
     * Write a key, encrypted with a password, to a string.
     *
     * @param string       $password   The password.
     * @param integer      $iterations The number of hash iterations to use.
     * @param KeyInterface $key        The key.
     *
     * @return string The key string.
     */
    public function writeStringWithPassword(
        $password,
        $iterations,
        KeyInterface $key
    );
}
