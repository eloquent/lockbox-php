<?php

/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Eloquent\Lockbox\Key;

/**
 * An abstract base class for implementing encryption keys.
 */
abstract class AbstractKey implements KeyInterface
{
    /**
     * Construct a new encryption key.
     *
     * @param resource $handle The key handle.
     */
    public function __construct($handle)
    {
        $this->handle = $handle;
        $this->details = openssl_pkey_get_details($handle);
    }

    public function __destruct()
    {
        openssl_free_key($this->handle());
    }

    /**
     * Get the key handle.
     *
     * @return resource The key handle.
     */
    public function handle()
    {
        return $this->handle;
    }

    /**
     * Get the size of the key in bits.
     *
     * @return integer The size of the key in bits.
     */
    public function size()
    {
        return $this->detail('bits');
    }

    /**
     * Get the modulus.
     *
     * @return string The modulus.
     */
    public function modulus()
    {
        return $this->rsaDetail('n');
    }

    /**
     * Get the public exponent.
     *
     * @return string The public exponent.
     */
    public function publicExponent()
    {
        return $this->rsaDetail('e');
    }

    /**
     * Get a specific detail from the key details.
     *
     * @param string $name The name of the detail.
     *
     * @return mixed                            The value of the detail.
     * @throws Exception\MissingDetailException If the detail is not present.
     */
    protected function detail($name)
    {
        if (!array_key_exists($name, $this->details)) {
            throw new Exception\MissingDetailException($name);
        }

        return $this->details[$name];
    }

    /**
     * Returns true if the requested detail exists in the RSA key details.
     *
     * @param string $name The name of the detail.
     *
     * @return mixed                            The value of the detail.
     * @throws Exception\MissingDetailException If no RSA key details are present.
     */
    protected function hasRsaDetail($name)
    {
        $rsaDetails = $this->detail('rsa');

        return array_key_exists($name, $rsaDetails);
    }

    /**
     * Get a specific detail from the RSA key details.
     *
     * @param string $name The name of the detail.
     *
     * @return mixed                            The value of the detail.
     * @throws Exception\MissingDetailException If the detail is not present.
     */
    protected function rsaDetail($name)
    {
        $rsaDetails = $this->detail('rsa');
        if (!array_key_exists($name, $rsaDetails)) {
            throw new Exception\MissingDetailException(
                sprintf('rsa.%s', $name)
            );
        }

        return $rsaDetails[$name];
    }

    private $handle;
    private $details;
}
