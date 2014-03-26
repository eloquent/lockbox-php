<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Random;

use Icecave\Isolator\Isolator;

/**
 * An abstract base class for implementing random sources via
 * mcrypt_create_iv().
 *
 * @see mcrypt_create_iv()
 */
abstract class AbstractMcryptRandomSource implements RandomSourceInterface
{
    /**
     * Construct a new mcrypt random source.
     *
     * @param integer       $source   The random source to use.
     * @param Isolator|null $isolator The isolator to use.
     */
    public function __construct($source, Isolator $isolator = null)
    {
        $this->source = $source;
        $this->isolator = Isolator::get($isolator);
    }

    /**
     * Get the random source.
     *
     * @return integer The random source.
     */
    public function source()
    {
        return $this->source;
    }

    /**
     * Generate random data.
     *
     * @param integer $size The data size in bytes.
     *
     * @return string The random data.
     */
    public function generate($size)
    {
        return $this->isolator()->mcrypt_create_iv($size, $this->source());
    }

    /**
     * Get the isolator.
     *
     * @return Isolator The isolator.
     */
    protected function isolator()
    {
        return $this->isolator;
    }

    private $source;
    private $isolator;
}
