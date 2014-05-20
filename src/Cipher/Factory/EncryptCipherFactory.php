<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Cipher\Factory;

use Eloquent\Lockbox\Cipher\CipherInterface;
use Eloquent\Lockbox\Cipher\EncryptCipher;
use Eloquent\Lockbox\Cipher\Result\Factory\CipherResultFactory;
use Eloquent\Lockbox\Cipher\Result\Factory\CipherResultFactoryInterface;
use Eloquent\Lockbox\Padding\PadderInterface;
use Eloquent\Lockbox\Padding\PkcsPadding;
use Eloquent\Lockbox\Random\DevUrandom;
use Eloquent\Lockbox\Random\RandomSourceInterface;

/**
 * Creates encrypt ciphers that use keys.
 */
class EncryptCipherFactory implements CipherFactoryInterface
{
    /**
     * Get the static instance of this factory.
     *
     * @return CipherFactoryInterface The static factory.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new encrypt cipher factory.
     *
     * @param RandomSourceInterface|null        $randomSource  The random source to use.
     * @param PadderInterface|null              $padder        The padder to use.
     * @param CipherResultFactoryInterface|null $resultFactory The result factory to use.
     */
    public function __construct(
        RandomSourceInterface $randomSource = null,
        PadderInterface $padder = null,
        CipherResultFactoryInterface $resultFactory = null
    ) {
        if (null === $randomSource) {
            $randomSource = DevUrandom::instance();
        }
        if (null === $padder) {
            $padder = PkcsPadding::instance();
        }
        if (null === $resultFactory) {
            $resultFactory = CipherResultFactory::instance();
        }

        $this->randomSource = $randomSource;
        $this->padder = $padder;
        $this->resultFactory = $resultFactory;
    }

    /**
     * Get the random source.
     *
     * @return RandomSourceInterface The random source.
     */
    public function randomSource()
    {
        return $this->randomSource;
    }

    /**
     * Get the padder.
     *
     * @return PadderInterface The padder.
     */
    public function padder()
    {
        return $this->padder;
    }

    /**
     * Get the result factory.
     *
     * @return CipherResultFactoryInterface The result factory.
     */
    public function resultFactory()
    {
        return $this->resultFactory;
    }

    /**
     * Create a new cipher.
     *
     * @return CipherInterface The newly created cipher.
     */
    public function createCipher()
    {
        return new EncryptCipher(
            $this->randomSource(),
            $this->padder(),
            $this->resultFactory()
        );
    }

    private static $instance;
    private $randomSource;
    private $padder;
    private $resultFactory;
}
