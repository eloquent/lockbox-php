<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Padding;

use Eloquent\Liberator\Liberator;
use PHPUnit_Framework_TestCase;

class PkcsPaddingTest extends PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->padding = new PkcsPadding;
    }

    public function testConstructor()
    {
        $this->padding = new PkcsPadding(111);

        $this->assertSame(111, $this->padding->blockSize());
    }

    public function testConstructorDefaults()
    {
        $this->assertSame(16, $this->padding->blockSize());
    }

    public function testConstructorFailureBlockSizeNotInteger()
    {
        $this->setExpectedException('Eloquent\Lockbox\Padding\Exception\InvalidBlockSizeException');
        new PkcsPadding('foo');
    }

    public function testConstructorFailureBlockSizeTooSmall()
    {
        $this->setExpectedException('Eloquent\Lockbox\Padding\Exception\InvalidBlockSizeException');
        new PkcsPadding(0);
    }

    public function testConstructorFailureBlockSizeTooLarge()
    {
        $this->setExpectedException('Eloquent\Lockbox\Padding\Exception\InvalidBlockSizeException');
        new PkcsPadding(256);
    }

    public function paddingData()
    {
        //                                            data        blockSize padded
        return array(
            'Empty'                          => array('',         8,        '0808080808080808'),
            'Block size'                     => array('12345678', 8,        '31323334353637380808080808080808'),
            'Single byte'                    => array('1234567',  8,        '3132333435363701'),
            'Partial block'                  => array('1234',     8,        '3132333404040404'),

            'Minimum block size empty'       => array('',         1,        '01'),
            'Minimum block size single byte' => array('1',        1,        '3101'),
            'Maximum block size empty'       => array('',         255,      str_repeat('ff', 255)),
            'Maximum block size single byte' => array('1',        255,      '31' . str_repeat('fe', 254)),
        );
    }

    /**
     * @dataProvider paddingData
     */
    public function testPad($data, $blockSize, $padded)
    {
        $this->padding = new PkcsPadding($blockSize);

        $this->assertSame($padded, bin2hex($this->padding->pad($data)));
    }

    /**
     * @dataProvider paddingData
     */
    public function testUnpad($data, $blockSize, $padded)
    {
        $this->assertSame($data, $this->padding->unpad(pack('H*', $padded)));
    }

    public function unpadFailureData()
    {
        return array(
            'Empty'           => array(''),
            'No padding'      => array('31323334'),
            'Invalid padding' => array('3132333401040404'),
            'Zero padding'    => array('3132333400'),
        );
    }

    /**
     * @dataProvider unpadFailureData
     */
    public function testUnpadFailure($data)
    {
        $this->setExpectedException('Eloquent\Lockbox\Padding\Exception\InvalidPaddingException');
        $this->padding->unpad(pack('H*', $data));
    }

    public function testInstance()
    {
        $className = get_class($this->padding);
        Liberator::liberateClass($className)->instance = null;
        $instance = $className::instance();

        $this->assertInstanceOf($className, $instance);
        $this->assertSame($instance, $className::instance());
    }
}
