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
use Eloquent\Lockbox\Cipher\DecryptCipher;
use Eloquent\Lockbox\Cipher\Result\Factory\CipherResultFactory;
use Eloquent\Lockbox\Cipher\Result\Factory\CipherResultFactoryInterface;
use Eloquent\Lockbox\Padding\PkcsPadding;
use Eloquent\Lockbox\Padding\UnpadderInterface;

/**
 * Creates decrypt ciphers that use keys.
 */
class DecryptCipherFactory implements CipherFactoryInterface
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
     * Construct a new decrypt cipher factory.
     *
     * @param UnpadderInterface|null            $unpadder      The unpadder to use.
     * @param CipherResultFactoryInterface|null $resultFactory The result factory to use.
     */
    public function __construct(
        UnpadderInterface $unpadder = null,
        CipherResultFactoryInterface $resultFactory = null
    ) {
        if (null === $unpadder) {
            $unpadder = PkcsPadding::instance();
        }
        if (null === $resultFactory) {
            $resultFactory = CipherResultFactory::instance();
        }

        $this->unpadder = $unpadder;
        $this->resultFactory = $resultFactory;
    }

    /**
     * Get the unpadder.
     *
     * @return UnpadderInterface The unpadder.
     */
    public function unpadder()
    {
        return $this->unpadder;
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
        return new DecryptCipher($this->unpadder(), $this->resultFactory());
    }

    private static $instance;
    private $randomSource;
    private $unpadder;
    private $resultFactory;
}
