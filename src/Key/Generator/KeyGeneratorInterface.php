<?php // @codeCoverageIgnoreStart

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Key\Generator;

use Eloquent\Lockbox\Key\Exception\InvalidKeyParameterExceptionInterface;
use Eloquent\Lockbox\Key\KeyInterface;

/**
 * The interface implemented by encryption key generators.
 */
interface KeyGeneratorInterface
{
    /**
     * Generate a new key.
     *
     * @param string|null  $name              The name.
     * @param string|null  $description       The description.
     * @param integer|null $encryptSecretBits The size of the encrypt secret in bits.
     * @param integer|null $authSecretBits    The size of the auth secret in bits.
     *
     * @return KeyInterface                          The generated key.
     * @throws InvalidKeyParameterExceptionInterface If the supplied arguments are invalid.
     */
    public function generateKey(
        $name = null,
        $description = null,
        $encryptSecretBits = null,
        $authSecretBits = null
    );
}
