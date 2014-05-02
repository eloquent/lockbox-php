<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Cipher;

use Eloquent\Lockbox\Key\KeyInterface;
use Eloquent\Lockbox\Padding\PadderInterface;

/**
 * Encrypts data with a key.
 */
class EncryptCipher extends AbstractEncryptCipher
{
    /**
     * Construct a new encrypt cipher.
     *
     * @param KeyInterface         $key    The key to encrypt with.
     * @param string               $iv     The initialization vector to use.
     * @param PadderInterface|null $padder The padder to use.
     */
    public function __construct(
        KeyInterface $key,
        $iv,
        PadderInterface $padder = null
    ) {
        parent::__construct($iv, $padder);

        $this->key = $key;
    }

    /**
     * Produce the key to use.
     *
     * @return KeyInterface The key.
     */
    protected function produceKey()
    {
        return $this->key;
    }

    /**
     * Get the encryption header.
     *
     * @param string $iv The initialization vector.
     *
     * @return string The header.
     */
    protected function header($iv)
    {
        return chr(1) . chr(1) . $iv;
    }

    private $key;
}
