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
 * A data structure for the password decrypt transform's context.
 */
class PasswordDecryptTransformContext
{
    public $mcryptModule;
    public $hashContext;
    public $hashBuffer = '';
    public $isVersionSeen = false;
    public $isTypeSeen = false;
    public $iterations = null;
    public $key = null;
    public $isInitialized = false;
    public $isHashFinalized = false;
}
