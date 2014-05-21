<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Password\Stream\Filter;

use Eloquent\Endec\Base64\Base64Url;
use Eloquent\Lockbox\Lockbox;
use Eloquent\Lockbox\Password\Password;
use PHPUnit_Framework_TestCase;

/**
 * @covers \Eloquent\Lockbox\Password\Stream\Filter\PasswordDecryptStreamFilter
 * @covers \Eloquent\Lockbox\Stream\Filter\AbstractCipherStreamFilter
 */
class PasswordDecryptStreamFilterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->parameters = new Password('password');
        $this->base64url = Base64Url::instance();

        Lockbox::registerFilters();
    }

    public function testFilter()
    {
        $path = tempnam(sys_get_temp_dir(), 'lockbox');
        $stream = fopen($path, 'wb');
        stream_filter_append($stream, 'lockbox.password-decrypt', STREAM_FILTER_WRITE, $this->parameters);
        fwrite($stream, $this->base64url->decode('AQIAAAAKMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIz'));
        fwrite($stream, $this->base64url->decode('NDEyMzQ1Njc4OTAxMjM0NTb5ax1Jk2Yssw3PVf4pI_FOAU5Fyd5KcOJbLQ8y--dEUE-B2gbtBSHcHX8yWrthbWMsDw'));
        fclose($stream);
        $actual = file_get_contents($path);
        unlink($path);

        $this->assertSame('foobarbazqux', $actual);
    }

    public function testFilterFailure()
    {
        $path = tempnam(sys_get_temp_dir(), 'lockbox');
        $stream = fopen($path, 'wb');
        stream_filter_append($stream, 'lockbox.password-decrypt', STREAM_FILTER_WRITE, $this->parameters);
        fwrite($stream, 'foobar');
        fwrite($stream, 'bazqux');
        fclose($stream);
        $actual = file_get_contents($path);
        unlink($path);

        $this->assertSame('', $actual);
    }
}
