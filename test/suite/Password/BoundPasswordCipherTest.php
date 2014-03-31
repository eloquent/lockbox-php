<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Password;

use PHPUnit_Framework_TestCase;

class BoundPasswordCipherTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->innerCipher = new PasswordCipher;
        $this->cipher = new BoundPasswordCipher('password', 1000, $this->innerCipher);
    }

    public function testConstructor()
    {
        $this->assertSame('password', $this->cipher->password());
        $this->assertSame(1000, $this->cipher->iterations());
        $this->assertSame($this->innerCipher, $this->cipher->cipher());
    }

    public function testConstructorDefaults()
    {
        $this->cipher = new BoundPasswordCipher('password', 1000);

        $this->assertSame(PasswordCipher::instance(), $this->cipher->cipher());
    }

    public function encryptionData()
    {
        return array(
            'Empty string' => array(''),
            'Short data'   => array('foobar'),
            'Long data'    => array(str_repeat('A', 8192)),
        );
    }

    /**
     * @dataProvider encryptionData
     */
    public function testEncryptDecrypt($data)
    {
        $encrypted = $this->cipher->encrypt($data);
        $decrypted = $this->cipher->decrypt($encrypted);

        $this->assertSame(array($data, 1000), $decrypted);
    }
}
