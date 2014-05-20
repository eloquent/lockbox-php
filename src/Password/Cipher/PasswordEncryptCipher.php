<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Password\Cipher;

use Eloquent\Lockbox\Cipher\AbstractEncryptCipher;
use Eloquent\Lockbox\Cipher\Exception\UnsupportedCipherParametersException;
use Eloquent\Lockbox\Cipher\Parameters\CipherParametersInterface;
use Eloquent\Lockbox\Cipher\Result\Factory\CipherResultFactoryInterface;
use Eloquent\Lockbox\Key\KeyDeriver;
use Eloquent\Lockbox\Key\KeyDeriverInterface;
use Eloquent\Lockbox\Padding\PadderInterface;
use Eloquent\Lockbox\Password\Cipher\Parameters\PasswordEncryptParametersInterface;
use Eloquent\Lockbox\Random\RandomSourceInterface;

/**
 * Encrypts data with a password.
 */
class PasswordEncryptCipher extends AbstractEncryptCipher
{
    /**
     * Construct a new password encrypt cipher.
     *
     * @param RandomSourceInterface|null        $randomSource  The random source to use.
     * @param KeyDeriverInterface|null          $keyDeriver    The key deriver to use.
     * @param PadderInterface|null              $padder        The padder to use.
     * @param CipherResultFactoryInterface|null $resultFactory The result factory to use.
     */
    public function __construct(
        RandomSourceInterface $randomSource = null,
        KeyDeriverInterface $keyDeriver = null,
        PadderInterface $padder = null,
        CipherResultFactoryInterface $resultFactory = null
    ) {
        if (null === $keyDeriver) {
            $keyDeriver = KeyDeriver::instance();
        }

        parent::__construct($randomSource, $padder, $resultFactory);

        $this->keyDeriver = $keyDeriver;
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
     * Initialize this cipher.
     *
     * @param CipherParametersInterface $parameters The parameters to use.
     *
     * @throws UnsupportedCipherParametersException If unsupported parameters are supplied.
     */
    public function initialize(CipherParametersInterface $parameters)
    {
        if (!$parameters instanceof PasswordEncryptParametersInterface) {
            throw new UnsupportedCipherParametersException($this, $parameters);
        }

        $this->iterations = $parameters->iterations();

        list($key, $this->salt) = $this->keyDeriver()->deriveKeyFromPassword(
            $parameters->password(),
            $this->iterations,
            $parameters->salt()
        );

        $this->doInitialize($key, $parameters->iv());
    }

    /**
     * Get the encryption header.
     *
     * @param string $iv The initialization vector.
     *
     * @return string The header.
     */
    protected function header($iv)
    {
        return chr(1) . chr(2) . pack('N', $this->iterations) . $this->salt .
            $iv;
    }

    private $keyDeriver;
    private $iterations;
    private $salt;
}
