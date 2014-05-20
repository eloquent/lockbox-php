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

use Eloquent\Lockbox\Key\Exception\KeyWriteException;
use Eloquent\Lockbox\Password\Cipher\Parameters\PasswordEncryptParametersInterface;

/**
 * The interface implemented by encrypted key writers.
 */
interface EncryptedKeyWriterInterface extends KeyWriterInterface
{
    /**
     * Write a key, encrypted with a password, to the supplied path.
     *
     * @param KeyInterface                       $key        The key.
     * @param PasswordEncryptParametersInterface $parameters The encrypt parameters.
     * @param string                             $path       The path to write to.
     *
     * @throws KeyWriteException If the key cannot be written.
     */
    public function writeFileWithPassword(
        KeyInterface $key,
        PasswordEncryptParametersInterface $parameters,
        $path
    );

    /**
     * Write a key, encrypted with a password, to the supplied stream.
     *
     * @param KeyInterface                       $key        The key.
     * @param PasswordEncryptParametersInterface $parameters The encrypt parameters.
     * @param stream                             $stream     The stream to write to.
     * @param string|null                        $path       The path, if known.
     *
     * @throws KeyWriteException If the key cannot be written.
     */
    public function writeStreamWithPassword(
        KeyInterface $key,
        PasswordEncryptParametersInterface $parameters,
        $stream,
        $path = null
    );

    /**
     * Write a key, encrypted with a password, to a string.
     *
     * @param KeyInterface                       $key        The key.
     * @param PasswordEncryptParametersInterface $parameters The encrypt parameters.
     *
     * @return string The key string.
     */
    public function writeStringWithPassword(
        KeyInterface $key,
        PasswordEncryptParametersInterface $parameters
    );
}
