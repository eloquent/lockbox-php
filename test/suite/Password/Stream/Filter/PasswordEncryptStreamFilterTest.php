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
use Eloquent\Lockbox\Password\Cipher\Parameters\PasswordEncryptParameters;
use Eloquent\Lockbox\Password\Password;
use PHPUnit_Framework_TestCase;

/**
 * @covers \Eloquent\Lockbox\Password\Stream\Filter\PasswordEncryptStreamFilter
 * @covers \Eloquent\Lockbox\Stream\Filter\AbstractCipherStreamFilter
 */
class PasswordEncryptStreamFilterTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->password = new Password('password');
        $this->iterations = 10;
        $this->salt = '1234567890123456789012345678901234567890123456789012345678901234';
        $this->iv = '1234567890123456';
        $this->parameters = new PasswordEncryptParameters($this->password, $this->iterations, $this->salt, $this->iv);
        $this->base64url = Base64Url::instance();

        Lockbox::registerFilters();
    }

    public function testFilter()
    {
        $path = tempnam(sys_get_temp_dir(), 'lockbox');
        $stream = fopen($path, 'wb');
        stream_filter_append($stream, 'lockbox.password-encrypt', STREAM_FILTER_WRITE, $this->parameters);
        fwrite($stream, 'foobar');
        fwrite($stream, 'bazqux');
        fclose($stream);
        $actual = file_get_contents($path);
        unlink($path);

        $this->assertSame(
            'AQIAAAAKMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDEyMzQ1Njc4OTAxMjM0NTb5ax1Jk2Yssw3PVf4pI_FOAU5Fyd5KcOJbLQ8y--dEUE-B2gbtBSHcHX8yWrthbWMsDw',
            $this->base64url->encode($actual)
        );
    }
}
