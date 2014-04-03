<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Padding;

/**
 * The interface implemented by unpadders.
 */
interface UnpadderInterface
{
    /**
     * Remove padding from the supplied data.
     *
     * @param string $data The padded data.
     *
     * @return string                            The unpadded data.
     * @throws Exception\InvalidPaddingException If the padding is invalid.
     */
    public function unpad($data);
}
