<?php // @codeCoverageIgnoreStart

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
 * The interface implemented by encryption key factories.
 */
interface KeyFactoryInterface
{
    /**
     * Create a new key from existing key data.
     *
     * @param string      $encryptSecret The encrypt secret.
     * @param string      $authSecret    The auth secret.
     * @param string|null $name          The name.
     * @param string|null $description   The description.
     *
     * @return KeyInterface                          The key.
     * @throws InvalidKeyParameterExceptionInterface If the supplied arguments are invalid.
     */
    public function createKey(
        $encryptSecret,
        $authSecret,
        $name = null,
        $description = null
    );
}
