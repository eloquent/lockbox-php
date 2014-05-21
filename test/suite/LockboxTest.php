<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox;

use Icecave\Isolator\Isolator;
use Phake;
use PHPUnit_Framework_TestCase;

class LockboxTest extends PHPUnit_Framework_TestCase
{
    public function testRegisterFilters()
    {
        $isolator = Phake::mock(Isolator::className());
        Lockbox::registerFilters($isolator);

        Phake::verify($isolator)->stream_filter_register(
            'lockbox.encrypt',
            'Eloquent\Lockbox\Stream\Filter\EncryptStreamFilter'
        );
        Phake::verify($isolator)->stream_filter_register(
            'lockbox.decrypt',
            'Eloquent\Lockbox\Stream\Filter\DecryptStreamFilter'
        );
        Phake::verify($isolator)->stream_filter_register(
            'lockbox.password-encrypt',
            'Eloquent\Lockbox\Password\Stream\Filter' .
            '\PasswordEncryptStreamFilter'
        );
        Phake::verify($isolator)->stream_filter_register(
            'lockbox.password-decrypt',
            'Eloquent\Lockbox\Password\Stream\Filter' .
            '\PasswordDecryptStreamFilter'
        );
    }
}
