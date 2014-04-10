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
 * A data structure for the encrypt transform's context.
 */
class EncryptTransformContext
{
    public $mcryptModule;
    public $hashAlgorithm;
    public $hashContext;
    public $encryptBuffer = '';
    public $encryptBufferSize = 0;
    public $ciphertextBuffer = '';
    public $outputBuffer = '';
}
