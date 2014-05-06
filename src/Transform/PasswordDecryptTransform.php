<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Transform;

use Eloquent\Confetti\AbstractTransform;
use Eloquent\Lockbox\Cipher\CipherInterface;
use Eloquent\Lockbox\Result\DecryptionResultInterface;

/**
 * A data transform for decryption of streaming data with a password.
 */
class PasswordDecryptTransform extends AbstractTransform implements
    DecryptTransformInterface
{
    /**
     * Construct a new password Decrypt data transform.
     *
     * @param CipherInterface $cipher The cipher to use.
     */
    public function __construct(CipherInterface $cipher)
    {
        $this->cipher = $cipher;
    }

    /**
     * Get the cipher.
     *
     * @return CipherInterface The cipher.
     */
    public function cipher()
    {
        return $this->cipher;
    }

    /**
     * Transform the supplied data.
     *
     * This method may transform only part of the supplied data. The return
     * value includes information about how much data was actually consumed. The
     * transform can be forced to consume all data by passing a boolean true as
     * the $isEnd argument.
     *
     * The $context argument will initially be null, but any value assigned to
     * this variable will persist until the stream transformation is complete.
     * It can be used as a place to store state, such as a buffer.
     *
     * It is guaranteed that this method will be called with $isEnd = true once,
     * and only once, at the end of the stream transformation.
     *
     * @param string  $data     The data to transform.
     * @param mixed   &$context An arbitrary context value.
     * @param boolean $isEnd    True if all supplied data must be transformed.
     *
     * @return tuple<string,integer,mixed> A 3-tuple of the transformed data, the number of bytes consumed, and any resulting error.
     */
    public function transform($data, &$context, $isEnd = false)
    {
        $size = strlen($data);

        if ($isEnd) {
            $data = $this->cipher->finalize($data);
        } else {
            $data = $this->cipher->process($data);
        }

        $result = $this->cipher->result();
        if ($result && !$result->isSuccessful()) {
            $error = $result;
        } else {
            $error = null;
        }

        return array($data, $size, $error);
    }

    /**
     * Get the decryption result.
     *
     * @return DecryptionResultInterface|null The decryption result, or null if not yet known.
     */
    public function result()
    {
        return $this->cipher()->result();
    }

    private $cipher;
}
