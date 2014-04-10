<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox;

use Eloquent\Confetti\TransformStreamInterface;
use Eloquent\Lockbox\Comparator\SlowStringComparator;
use Eloquent\Lockbox\Result\DecryptionResult;
use Eloquent\Lockbox\Result\DecryptionResultInterface;
use Eloquent\Lockbox\Result\DecryptionResultType;
use Eloquent\Lockbox\Stream\RawDecryptStream;
use Eloquent\Lockbox\Transform\Factory\DecryptTransformFactory;
use Eloquent\Lockbox\Transform\Factory\KeyTransformFactoryInterface;

/**
 * Decrypts raw data using keys.
 */
class RawDecrypter implements DecrypterInterface
{
    /**
     * Get the static instance of this decrypter.
     *
     * @return DecrypterInterface The static decrypter.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new raw decrypter.
     *
     * @param KeyTransformFactoryInterface|null $transformFactory The transform factory to use.
     */
    public function __construct(
        KeyTransformFactoryInterface $transformFactory = null
    ) {
        if (null === $transformFactory) {
            $transformFactory = DecryptTransformFactory::instance();
        }

        $this->transformFactory = $transformFactory;
    }

    /**
     * Get the transform factory.
     *
     * @return KeyTransformFactoryInterface The transform factory.
     */
    public function transformFactory()
    {
        return $this->transformFactory;
    }

    /**
     * Decrypt a data packet.
     *
     * @param Key\KeyInterface $key  The key to decrypt with.
     * @param string           $data The data to decrypt.
     *
     * @return DecryptionResultInterface The decryption result.
     */
    public function decrypt(Key\KeyInterface $key, $data)
    {
        $size = strlen($data);
        $ciphertextSize = $size - $key->authenticationSecretBytes() - 18;

        if ($ciphertextSize < 18 || 0 !== $ciphertextSize % 18) {
            return new DecryptionResult(
                DecryptionResultType::INVALID_SIZE()
            );
        }

        $hashAlgorithm = 'sha' . $key->authenticationSecretBits();
        $hashContext = hash_init(
            $hashAlgorithm,
            HASH_HMAC,
            $key->authenticationSecret()
        );
        hash_update($hashContext, substr($data, 0, 18));

        $ciphertext = substr($data, 18, $ciphertextSize);

        $expectedBlockMacs = '';
        $actualBlockMacs = '';
        foreach (str_split($ciphertext, 18) as $block) {
            list($block, $blockMac) = str_split($block, 16);

            $expectedBlockMacs .= $blockMac;
            $actualBlockMacs .= substr(
                hash_hmac(
                    $hashAlgorithm,
                    $block,
                    $key->authenticationSecret(),
                    true
                ),
                0,
                2
            );

            hash_update($hashContext, $block);
        }

        if (
            !SlowStringComparator::isEqual(
                substr($data, $ciphertextSize + 18) . $expectedBlockMacs,
                hash_final($hashContext, true) . $actualBlockMacs
            )
        ) {
            return new DecryptionResult(DecryptionResultType::INVALID_MAC());
        }

        $transform = $this->transformFactory()->createTransform($key);

        list($data) = $transform->transform($data, $context, true);
        $result = $transform->result();
        if ($result->isSuccessful()) {
            $result->setData($data);
        }

        return $result;
    }

    /**
     * Create a new decrypt stream.
     *
     * @param Key\KeyInterface $key The key to decrypt with.
     *
     * @return TransformStreamInterface The newly created decrypt stream.
     */
    public function createDecryptStream(Key\KeyInterface $key)
    {
        return new RawDecryptStream(
            $this->transformFactory()->createTransform($key)
        );
    }

    private static $instance;
    private $transformFactory;
}
