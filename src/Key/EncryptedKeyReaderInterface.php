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

use Eloquent\Lockbox\Key\Exception\KeyReadException;
use Eloquent\Lockbox\Password\PasswordInterface;

/**
 * The interface implemented by encrypted key readers.
 */
interface EncryptedKeyReaderInterface extends KeyReaderInterface
{
    /**
     * Read a key from the supplied path, and decrypt with a password.
     *
     * @param PasswordInterface $password The password.
     * @param string            $path     The path to read from.
     *
     * @return KeyInterface     The key.
     * @throws KeyReadException If the key cannot be read, or if the key is invalid.
     */
    public function readFileWithPassword(PasswordInterface $password, $path);

    /**
     * Read a key from the supplied path, and decrypt with an optional password.
     *
     * If a password is required to read the key, it will be acquired by
     * executing the callback.
     *
     * @param callable $callback The password callback.
     * @param string   $path     The path to read from.
     *
     * @return KeyInterface     The key.
     * @throws KeyReadException If the key cannot be read, or if the key is invalid.
     */
    public function readFileWithPasswordCallback($callback, $path);

    /**
     * Read a key from the supplied stream, and decrypt with a password.
     *
     * @param PasswordInterface $password The password.
     * @param stream            $stream   The stream to read from.
     * @param string|null       $path     The path, if known.
     *
     * @return KeyInterface     The key.
     * @throws KeyReadException If the key cannot be read, or if the key is invalid.
     */
    public function readStreamWithPassword(
        PasswordInterface $password,
        $stream,
        $path = null
    );

    /**
     * Read a key from the supplied stream, and decrypt with an optional
     * password.
     *
     * If a password is required to read the key, it will be acquired by
     * executing the callback.
     *
     * @param callable    $callback The password callback.
     * @param stream      $stream   The stream to read from.
     * @param string|null $path     The path, if known.
     *
     * @return KeyInterface     The key.
     * @throws KeyReadException If the key cannot be read, or if the key is invalid.
     */
    public function readStreamWithPasswordCallback(
        $callback,
        $stream,
        $path = null
    );

    /**
     * Read a key from the supplied string, and decrypt with a password.
     *
     * @param PasswordInterface $password The password.
     * @param string            $data     The string to read from.
     * @param string|null       $path     The path, if known.
     *
     * @return KeyInterface     The key.
     * @throws KeyReadException If the key cannot be read, or if the key is invalid.
     */
    public function readStringWithPassword(
        PasswordInterface $password,
        $data,
        $path = null
    );

    /**
     * Read a key from the supplied string, and decrypt with a password.
     *
     * @param callable    $callback The password callback.
     * @param string      $data     The string to read from.
     * @param string|null $path     The path, if known.
     *
     * @return KeyInterface     The key.
     * @throws KeyReadException If the key cannot be read, or if the key is invalid.
     */
    public function readStringWithPasswordCallback(
        $callback,
        $data,
        $path = null
    );
}
