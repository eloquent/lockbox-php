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

use Eloquent\Lockbox\Key\Exception\InvalidKeyParameterExceptionInterface;

/**
 * The interface implemented by encryption key generators.
 */
interface KeyGeneratorInterface
{
    /**
     * Generate a new key.
     *
     * @param string|null  $name                     The name.
     * @param string|null  $description              The description.
     * @param integer|null $encryptionSecretBits     The size of the encryption secret in bits.
     * @param integer|null $authenticationSecretBits The size of the authentication secret in bits.
     *
     * @return KeyInterface                          The generated key.
     * @throws InvalidKeyParameterExceptionInterface If the supplied arguments are invalid.
     */
    public function generateKey(
        $name = null,
        $description = null,
        $encryptionSecretBits = null,
        $authenticationSecretBits = null
    );
}
