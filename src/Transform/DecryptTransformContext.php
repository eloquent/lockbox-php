<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Transform;

/**
 * A data structure for the decrypt transform's context.
 */
class DecryptTransformContext
{
    public $mcryptModule;
    public $hashAlgorithm;
    public $hashContext;
    public $hashSize;
    public $isVersionSeen = false;
    public $isTypeSeen = false;
    public $isInitialized = false;
    public $isHashFinalized = false;
}
