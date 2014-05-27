<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Password\Cipher\Factory;

use Eloquent\Lockbox\Cipher\CipherInterface;
use Eloquent\Lockbox\Cipher\Factory\CipherFactoryInterface;
use Eloquent\Lockbox\Cipher\Result\Factory\CipherResultFactoryInterface;
use Eloquent\Lockbox\Key\Deriver\KeyDeriver;
use Eloquent\Lockbox\Key\Deriver\KeyDeriverInterface;
use Eloquent\Lockbox\Padding\PkcsPadding;
use Eloquent\Lockbox\Padding\UnpadderInterface;
use Eloquent\Lockbox\Password\Cipher\PasswordDecryptCipher;
use Eloquent\Lockbox\Password\Cipher\Result\Factory\PasswordDecryptResultFactory;

/**
 * Creates decrypt ciphers that use passwords.
 */
class PasswordDecryptCipherFactory implements CipherFactoryInterface
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
     * Construct a new password decrypt cipher factory.
     *
     * @param integer|null                      $maxIterations The maximum number of hash iterations to allow.
     * @param KeyDeriverInterface|null          $keyDeriver    The key deriver to use.
     * @param UnpadderInterface|null            $unpadder      The unpadder to use.
     * @param CipherResultFactoryInterface|null $resultFactory The result factory to use.
     */
    public function __construct(
        $maxIterations = null,
        KeyDeriverInterface $keyDeriver = null,
        UnpadderInterface $unpadder = null,
        CipherResultFactoryInterface $resultFactory = null
    ) {
        if (null === $maxIterations) {
            $maxIterations = 4194304;
        }
        if (null === $keyDeriver) {
            $keyDeriver = KeyDeriver::instance();
        }
        if (null === $unpadder) {
            $unpadder = PkcsPadding::instance();
        }
        if (null === $resultFactory) {
            $resultFactory = PasswordDecryptResultFactory::instance();
        }

        $this->maxIterations = $maxIterations;
        $this->keyDeriver = $keyDeriver;
        $this->unpadder = $unpadder;
        $this->resultFactory = $resultFactory;
    }

    /**
     * Get the maximum number of hash iterations.
     *
     * @return integer The maximum iterations.
     */
    public function maxIterations()
    {
        return $this->maxIterations;
    }

    /**
     * Get the key deriver.
     *
     * @return KeyDeriverInterface The key deriver.
     */
    public function keyDeriver()
    {
        return $this->keyDeriver;
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
        return new PasswordDecryptCipher(
            $this->maxIterations(),
            $this->keyDeriver(),
            $this->unpadder(),
            $this->resultFactory()
        );
    }

    private static $instance;
    private $maxIterations;
    private $keyDeriver;
    private $unpadder;
    private $resultFactory;
}
