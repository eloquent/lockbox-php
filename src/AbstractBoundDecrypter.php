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

use Eloquent\Lockbox\Cipher\Parameters\CipherParametersInterface;
use Eloquent\Lockbox\Cipher\Result\CipherResultInterface;
use Eloquent\Lockbox\Stream\CipherStreamInterface;

/**
 * An abstract base class for implementing bound decrypters.
 */
abstract class AbstractBoundDecrypter implements BoundDecrypterInterface
{
    /**
     * Construct a new bound decrypter.
     *
     * @param CipherParametersInterface $parameters The parameters to use.
     * @param DecrypterInterface        $decrypter  The decrypter to use.
     */
    public function __construct(
        CipherParametersInterface $parameters,
        DecrypterInterface $decrypter
    ) {
        $this->parameters = $parameters;
        $this->decrypter = $decrypter;
    }

    /**
     * Get the parameters.
     *
     * @return CipherParametersInterface The parameters.
     */
    public function parameters()
    {
        return $this->parameters;
    }

    /**
     * Get the decrypter.
     *
     * @return DecrypterInterface The decrypter;
     */
    public function decrypter()
    {
        return $this->decrypter;
    }

    /**
     * Decrypt a data packet.
     *
     * @param string $data The data to decrypt.
     *
     * @return CipherResultInterface The decrypt result.
     */
    public function decrypt($data)
    {
        return $this->decrypter()->decrypt($this->parameters(), $data);
    }

    /**
     * Create a new decrypt stream.
     *
     * @return CipherStreamInterface The newly created decrypt stream.
     */
    public function createDecryptStream()
    {
        return $this->decrypter()->createDecryptStream($this->parameters());
    }

    private $parameters;
    private $decrypter;
}
