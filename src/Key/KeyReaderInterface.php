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
 * The interface implemented by key readers.
 */
interface KeyReaderInterface
{
    /**
     * Read a key from the supplied path.
     *
     * @param string $path The path to read from.
     *
     * @return KeyInterface               The key.
     * @throws Exception\KeyReadException If the key cannot be read, or if the key is invalid.
     */
    public function readFile($path);

    /**
     * Read a key from the supplied stream.
     *
     * @param stream      $stream The stream to read from.
     * @param string|null $path   The path, if known.
     *
     * @return KeyInterface               The key.
     * @throws Exception\KeyReadException If the key cannot be read, or if the key is invalid.
     */
    public function readStream($stream, $path = null);
}
