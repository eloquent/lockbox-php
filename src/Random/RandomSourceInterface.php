<?php // @codeCoverageIgnoreStart

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Random;

/**
 * The interface implemented by random data sources.
 */
interface RandomSourceInterface
{
    /**
     * Generate random data.
     *
     * @param integer $size The data size in bytes.
     *
     * @return string The random data.
     */
    public function generate($size);
}
