<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Cipher\Result\Factory;

use Eloquent\Lockbox\Cipher\Result\CipherResultType;

/**
 * The interface implemented by cipher result factories.
 */
interface CipherResultFactoryInterface
{
    /**
     * Construct a new cipher result.
     *
     * @param CipherResultType $type The result type.
     * @param string|null      $data The data, or null if unavailable.
     */
    public function createResult(CipherResultType $type, $data = null);
}
