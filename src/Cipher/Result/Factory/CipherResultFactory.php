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

use Eloquent\Lockbox\Cipher\Result\CipherResult;
use Eloquent\Lockbox\Cipher\Result\CipherResultInterface;
use Eloquent\Lockbox\Cipher\Result\CipherResultType;

/**
 * Creates cipher results.
 */
class CipherResultFactory implements CipherResultFactoryInterface
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
        return new CipherResult($type);
    }

    private static $instance;
}
