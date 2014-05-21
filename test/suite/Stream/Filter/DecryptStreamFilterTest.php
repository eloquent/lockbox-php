<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Stream\Filter;

use Eloquent\Endec\Base64\Base64Url;
use Eloquent\Lockbox\Key\Key;
use Eloquent\Lockbox\Lockbox;
use PHPUnit_Framework_TestCase;

/**
 * @covers \Eloquent\Lockbox\Stream\Filter\DecryptStreamFilter
 * @covers \Eloquent\Lockbox\Stream\Filter\AbstractCipherStreamFilter
 */
class DecryptStreamFilterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->parameters = new Key('1234567890123456', '1234567890123456789012345678');
        $this->base64url = Base64Url::instance();

        Lockbox::registerFilters();
    }

    public function testFilter()
    {
        $path = tempnam(sys_get_temp_dir(), 'lockbox');
        $stream = fopen($path, 'wb');
        stream_filter_append($stream, 'lockbox.decrypt', STREAM_FILTER_WRITE, $this->parameters);
        fwrite($stream, $this->base64url->decode('AQExMjM0NTY3ODkwMTIzNDU2q8Ujr8BN2S2S7--KpCyx'));
        fwrite($stream, $this->base64url->decode('SCAMajW4rlF-TF0eVTEQU5SubSD0-VIlIGBMWk1JPA'));
        fclose($stream);
        $actual = file_get_contents($path);
        unlink($path);

        $this->assertSame('foobarbazqux', $actual);
    }

    public function testFilterFailure()
    {
        $path = tempnam(sys_get_temp_dir(), 'lockbox');
        $stream = fopen($path, 'wb');
        stream_filter_append($stream, 'lockbox.decrypt', STREAM_FILTER_WRITE, $this->parameters);
        fwrite($stream, 'foobar');
        fwrite($stream, 'bazqux');
        fclose($stream);
        $actual = file_get_contents($path);
        unlink($path);

        $this->assertSame('', $actual);
    }
}
