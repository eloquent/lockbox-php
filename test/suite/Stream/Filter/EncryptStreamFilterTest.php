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
use Eloquent\Lockbox\Cipher\Parameters\EncryptParameters;
use Eloquent\Lockbox\Key\Key;
use Eloquent\Lockbox\Lockbox;
use PHPUnit_Framework_TestCase;

/**
 * @covers \Eloquent\Lockbox\Stream\Filter\EncryptStreamFilter
 * @covers \Eloquent\Lockbox\Stream\Filter\AbstractCipherStreamFilter
 */
class EncryptStreamFilterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->key = new Key('1234567890123456', '1234567890123456789012345678');
        $this->iv = '1234567890123456';
        $this->parameters = new EncryptParameters($this->key, $this->iv);
        $this->base64url = Base64Url::instance();

        Lockbox::registerFilters();
    }

    public function testFilter()
    {
        $path = tempnam(sys_get_temp_dir(), 'lockbox');
        $stream = fopen($path, 'wb');
        stream_filter_append($stream, 'lockbox.encrypt', STREAM_FILTER_WRITE, $this->parameters);
        fwrite($stream, 'foobar');
        fwrite($stream, 'bazqux');
        fclose($stream);
        $actual = file_get_contents($path);
        unlink($path);

        $this->assertSame(
            'AQExMjM0NTY3ODkwMTIzNDU2q8Ujr8BN2S2S7--KpCyxSCAMajW4rlF-TF0eVTEQU5SubSD0-VIlIGBMWk1JPA',
            $this->base64url->encode($actual)
        );
    }
}
