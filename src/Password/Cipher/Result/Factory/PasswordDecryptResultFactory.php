<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Password\Cipher\Result\Factory;

use Eloquent\Lockbox\Cipher\Result\CipherResultInterface;
use Eloquent\Lockbox\Cipher\Result\CipherResultType;
use Eloquent\Lockbox\Cipher\Result\Factory\CipherResultFactoryInterface;
use Eloquent\Lockbox\Password\Cipher\Result\PasswordDecryptResult;

/**
 * Creates password decrypt results.
 */
class PasswordDecryptResultFactory implements CipherResultFactoryInterface
{
    /**
     * Get the static instance of this factory.
     *
     * @return CipherResultFactoryInterface The static factory.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new cipher result.
     *
     * @param CipherResultType $type The result type.
     *
     * @return CipherResultInterface The newly created result.
     */
    public function createResult(CipherResultType $type)
    {
        return new PasswordDecryptResult($type);
    }

    private static $instance;
}
