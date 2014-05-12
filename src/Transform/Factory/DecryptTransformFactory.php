<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Transform\Factory;

use Eloquent\Confetti\TransformInterface;
use Eloquent\Lockbox\Cipher\DecryptCipher;
use Eloquent\Lockbox\Key\KeyInterface;
use Eloquent\Lockbox\Padding\PkcsPadding;
use Eloquent\Lockbox\Padding\UnpadderInterface;
use Eloquent\Lockbox\Transform\CipherTransform;

/**
 * Creates decrypt transforms that use keys.
 */
class DecryptTransformFactory implements KeyTransformFactoryInterface
{
    /**
     * Get the static instance of this factory.
     *
     * @return KeyTransformFactoryInterface The static factory.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }
    /**
     * Construct a new decrypt transform factory.
     *
     * @param UnpadderInterface|null $unpadder The unpadder to use.
     */
    public function __construct(UnpadderInterface $unpadder = null)
    {
        if (null === $unpadder) {
            $unpadder = PkcsPadding::instance();
        }

        $this->unpadder = $unpadder;
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
     * Create a new transform for the supplied key.
     *
     * @param KeyInterface $key The key to use.
     *
     * @return TransformInterface The newly created transform.
     */
    public function createTransform(KeyInterface $key)
    {
        $cipher = new DecryptCipher($this->unpadder());
        $cipher->initialize($key);

        return new CipherTransform($cipher);
    }

    private static $instance;
    private $unpadder;
}
