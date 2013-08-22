<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Key;

/**
 * The interface implemented by encryption keys.
 */
interface KeyInterface
{
    /**
     * Get the number of bits.
     *
     * @return integer The number of bits.
     */
    public function bits();

    /**
     * Get the size of envelopes produced by this key.
     *
     * @return integer The enveolpe size.
     */
    public function envelopeSize();
}
