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

use Eloquent\Confetti\TransformStreamInterface;
use Eloquent\Lockbox\Comparator\SlowStringComparator;
use Eloquent\Lockbox\Key\KeyDeriver;
use Eloquent\Lockbox\Key\KeyDeriverInterface;
use Eloquent\Lockbox\Padding\PkcsPadding;
use Eloquent\Lockbox\Padding\UnpadderInterface;
use Eloquent\Lockbox\Result\DecryptionResultType;
use Eloquent\Lockbox\Result\PasswordDecryptionResult;
use Eloquent\Lockbox\Result\PasswordDecryptionResultInterface;
use Eloquent\Lockbox\Stream\RawDecryptStream;
use Eloquent\Lockbox\Transform\Factory\PasswordDecryptTransformFactory;
use Eloquent\Lockbox\Transform\Factory\PasswordDecryptTransformFactoryInterface;

/**
 * Decrypts raw data using passwords.
 */
class RawPasswordDecrypter implements PasswordDecrypterInterface
{
    /**
     * Get the static instance of this decrypter.
     *
     * @return PasswordDecrypterInterface The static decrypter.
     */
    public static function instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Construct a new raw password decrypter.
     *
     * @param PasswordDecryptTransformFactoryInterface|null $transformFactory The transform factory to use.
     * @param KeyDeriverInterface|null                      $keyDeriver       The key deriver to use.
     * @param UnpadderInterface|null                        $unpadder         The unpadder to use.
     */
    public function __construct(
        PasswordDecryptTransformFactoryInterface $transformFactory = null,
        KeyDeriverInterface $keyDeriver = null,
        UnpadderInterface $unpadder = null
    ) {
        if (null === $transformFactory) {
            $transformFactory = PasswordDecryptTransformFactory::instance();
        }
        if (null === $keyDeriver) {
            $keyDeriver = KeyDeriver::instance();
        }
        if (null === $unpadder) {
            $unpadder = PkcsPadding::instance();
        }

        $this->transformFactory = $transformFactory;
        $this->keyDeriver = $keyDeriver;
        $this->unpadder = $unpadder;
    }

    /**
     * Get the transform factory.
     *
     * @return PasswordDecryptTransformFactoryInterface The transform factory.
     */
    public function transformFactory()
    {
        return $this->transformFactory;
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
     * Decrypt a data packet.
     *
     * @param string $password The password to decrypt with.
     * @param string $data     The data to decrypt.
     *
     * @return PasswordDecryptionResultInterface The decryption result.
     */
    public function decrypt($password, $data)
    {
        $size = strlen($data);
        if ($size < 118) {
            return new PasswordDecryptionResult(
                DecryptionResultType::INVALID_SIZE()
            );
        }

        $version = ord(substr($data, 0, 1));
        if (1 !== $version) {
            return new PasswordDecryptionResult(
                DecryptionResultType::UNSUPPORTED_VERSION()
            );
        }

        $type = ord(substr($data, 1, 1));
        if (2 !== $type) {
            return new PasswordDecryptionResult(
                DecryptionResultType::UNSUPPORTED_TYPE()
            );
        }

        $iterations = unpack('N', substr($data, 2, 4));
        $iterations = array_shift($iterations);

        list($key) = $this->keyDeriver()->deriveKeyFromPassword(
            $password,
            $iterations,
            substr($data, 6, 64)
        );

        $hash = hash_hmac(
            'sha' . $key->authenticationSecretBits(),
            substr($data, 0, $size - $key->authenticationSecretBytes()),
            $key->authenticationSecret(),
            true
        );

        if (
            !SlowStringComparator::isEqual(
                substr($data, $size - $key->authenticationSecretBytes()),
                $hash
            )
        ) {
            return new PasswordDecryptionResult(
                DecryptionResultType::INVALID_MAC()
            );
        }

        $data = mcrypt_decrypt(
            MCRYPT_RIJNDAEL_128,
            $key->encryptionSecret(),
            substr($data, 86, $size - 118),
            MCRYPT_MODE_CBC,
            substr($data, 70, 16)
        );

        list($isSuccessful, $data) = $this->unpadder()->unpad($data);
        if (!$isSuccessful) {
            return new PasswordDecryptionResult(
                DecryptionResultType::INVALID_PADDING()
            );
        }

        return new PasswordDecryptionResult(
            DecryptionResultType::SUCCESS(),
            $data,
            $iterations
        );
    }

    /**
     * Create a new decrypt stream.
     *
     * @param string $password The password to decrypt with.
     *
     * @return TransformStreamInterface The newly created decrypt stream.
     */
    public function createDecryptStream($password)
    {
        return new RawDecryptStream(
            $this->transformFactory()->createTransform($password)
        );
    }

    private static $instance;
    private $transformFactory;
    private $keyDeriver;
    private $unpadder;
}
