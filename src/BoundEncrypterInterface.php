<?php // @codeCoverageIgnoreStart

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox;

use Eloquent\Lockbox\Stream\CipherStreamInterface;

/**
 * The interface implemented by bound encrypters.
 */
interface BoundEncrypterInterface
{
    /**
     * Encrypt a data packet.
     *
     * @param string $data The data to encrypt.
     *
     * @return string The encrypted data.
     */
    public function encrypt($data);

    /**
     * Create a new encrypt stream.
     *
     * @return CipherStreamInterface The newly created encrypt stream.
     */
    public function createEncryptStream();
}
