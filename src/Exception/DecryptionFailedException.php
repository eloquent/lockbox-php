<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Exception;

use Eloquent\Endec\Transform\Exception\TransformExceptionInterface;
use Eloquent\Lockbox\Key\KeyInterface;
use Exception;

/**
 * Decryption failed.
 */
final class DecryptionFailedException extends Exception implements
    TransformExceptionInterface
{
    /**
     * Construct a new decryption failed exception.
     *
     * @param KeyInterface   $key      The key used to attempt decryption.
     * @param Exception|null $previous The cause, if available.
     */
    public function __construct(KeyInterface $key, Exception $previous = null)
    {
        $this->key = $key;

        if (null === $key->name()) {
            $message = 'Decryption failed.';
        } else {
            $message = sprintf(
                'Decryption failed for key %s.',
                var_export($key->name(), true)
            );
        }

        parent::__construct($message, 0, $previous);
    }

    /**
     * Get the key used to attempt decryption.
     *
     * @return KeyInterface The key.
     */
    public function key()
    {
        return $this->key;
    }

    private $key;
}
