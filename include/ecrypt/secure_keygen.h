/*
 * Copyright (c) 2019 Cossack Labs Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Securely generating random keys.
 * @file ecrypt/secure_keygen.h
 */

#ifndef ECRYPT_SECURE_KEYGEN_H
#define ECRYPT_SECURE_KEYGEN_H

#include <ecrypt/ecrypt_api.h>
#include <ecrypt/ecrypt_error.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup ECRYPT
 * @{
 * @defgroup ECRYPT_KEYS Secure key generation
 * Securely generating random symmetric keys and asymmetric key pairs.
 * @{
 */

/**
 * Generates a symmetric key.
 *
 * @param [out]     key         buffer for generated key
 * @param [in,out]  key_length  length of generated key in bytes
 *
 * New symmetric key is generated and written into `key` buffer which
 * must have at least `key_length` bytes available. Note that length
 * parameter is a _pointer_ to actual length value.
 *
 * You can pass NULL for `key` in order to determine appropriate buffer
 * length. In this case the length is written into provided location,
 * no key data is generated, and ECRYPT_BUFFER_TOO_SMALL is returned.
 *
 * @returns ECRYPT_SUCCESS if the key has been generated successfully
 * and written into `key`.
 *
 * @returns ECRYPT_BUFFER_TOO_SMALL if the key length has been written
 * to `key_length`.
 *
 * @exception ECRYPT_INVALID_PARAM if `key_length` is NULL.
 *
 * @exception ECRYPT_INVALID_PARAM if `key_length` is too big
 * for cryptographic backend to handle.
 *
 * @exception ECRYPT_BUFFER_TOO_SMALL if `key_length` is too small
 * to hold a generated key.
 *
 * @exception ECRYPT_FAIL if cryptographic backend was unable
 * to generate enough randomness to fill the entire buffer.
 *
 * @exception ECRYPT_NOT_SUPPORTED if cryptographic backend
 * does not support strong random number generation.
 *
 * @note Some backends might abort the process instead of returning
 * error codes if they are unable to generate random data.
 */
ECRYPT_API
ecrypt_status_t ecrypt_gen_sym_key(uint8_t* key, size_t* key_length);

/**
 * Generates an RSA key pair.
 *
 * @param [out]     private_key         buffer for private key
 * @param [in,out]  private_key_length  length of private key in bytes
 * @param [out]     public_key          buffer for public key
 * @param [in,out]  public_key_length   length of public key in bytes
 *
 * New RSA key pair is generated and written into `private_key` and
 * `public_key` buffers which must have at least `private_key_length`
 * and `public_key_length` bytes available respectively. Note that
 * length parameters are _pointers_ to actual length values.
 *
 * You can pass NULL for `private_key` and `public_key` in order to
 * determine appropriate buffer length. In this case the lengths are
 * written into provided locations, no key data is generated, and
 * ECRYPT_BUFFER_TOO_SMALL is returned.
 *
 * @returns ECRYPT_SUCCESS if the keys have been generated successfully
 * and written to `private_key` and `public_key`.
 *
 * @returns ECRYPT_BUFFER_TOO_SMALL if the key lengths have been written
 * to `private_key_length` and `public_key_length`.
 *
 * @exception ECRYPT_FAIL if key generation has failed.
 *
 * @exception ECRYPT_INVALID_PARAM if `private_key_length` or
 * `public_key_length` is NULL.
 *
 * @exception ECRYPT_BUFFER_TOO_SMALL if `private_key` and `public_key`
 * are not NULL, but `private_key_length` or `public_key_length` in not
 * sufficient to hold a generated key.
 */
ECRYPT_API
ecrypt_status_t ecrypt_gen_rsa_key_pair(uint8_t* private_key,
                                        size_t* private_key_length,
                                        uint8_t* public_key,
                                        size_t* public_key_length);

/**
 * Generates an EC key pair.
 *
 * @param [out]     private_key         buffer for private key
 * @param [in,out]  private_key_length  length of private key in bytes
 * @param [out]     public_key          buffer for public key
 * @param [in,out]  public_key_length   length of public key in bytes
 *
 * New EC key pair is generated and written into `private_key` and
 * `public_key` buffers which must have at least `private_key_length`
 * and `public_key_length` bytes available respectively. Note that
 * length parameters are _pointers_ to actual length values.
 *
 * You can pass NULL for `private_key` and `public_key` in order to
 * determine appropriate buffer length. In this case the lengths are
 * written into provided locations, no key data is generated, and
 * ECRYPT_BUFFER_TOO_SMALL is returned.
 *
 * @returns ECRYPT_SUCCESS if the keys have been generated successfully
 * and written to `private_key` and `public_key`.
 *
 * @returns ECRYPT_BUFFER_TOO_SMALL if the key lengths have been written
 * to `private_key_length` and `public_key_length`.
 *
 * @exception ECRYPT_FAIL if key generation has failed.
 *
 * @exception ECRYPT_INVALID_PARAM if `private_key_length` or
 * `public_key_length` is NULL.
 *
 * @exception ECRYPT_BUFFER_TOO_SMALL if `private_key` and `public_key`
 * are not NULL, but `private_key_length` or `public_key_length` in not
 * sufficient to hold a generated key.
 */
ECRYPT_API
ecrypt_status_t ecrypt_gen_ec_key_pair(uint8_t* private_key,
                                       size_t* private_key_length,
                                       uint8_t* public_key,
                                       size_t* public_key_length);

/**
 * Kind of an asymmetric Ecrypt key.
 */
typedef enum ecrypt_key_kind {
    /** Invalid key buffer. */
    ECRYPT_KEY_INVALID,
    /** Private RSA key. */
    ECRYPT_KEY_RSA_PRIVATE,
    /** Public RSA key. */
    ECRYPT_KEY_RSA_PUBLIC,
    /** Private EC key. */
    ECRYPT_KEY_EC_PRIVATE,
    /** Public EC key. */
    ECRYPT_KEY_EC_PUBLIC,
} ecrypt_key_kind_t;

/**
 * Returns kind of an asymmetric Ecrypt key.
 *
 * @param [in]  key     key buffer
 * @param [in]  length  length of key in bytes
 *
 * @return corresponding key kind if the buffer contains a key,
 * or ECRYPT_KEY_INVALID otherwise.
 *
 * @exception ECRYPT_KEY_INVALID if `key` is NULL.
 */
ECRYPT_API
ecrypt_key_kind_t ecrypt_get_asym_key_kind(const uint8_t* key, size_t length);

/**
 * Validates an asymmetric Ecrypt key.
 *
 * @param [in]  key     key buffer to validate
 * @param [in]  length  length of key in bytes
 *
 * @return ECRYPT_SUCCESS if the buffer contains a valid Ecrypt key,
 * or ECRYPT_INVALID_PARAMETER if it does not.
 *
 * @exception ECRYPT_INVALID_PARAMETER if `key` is NULL.
 */
ECRYPT_API
ecrypt_status_t ecrypt_is_valid_asym_key(const uint8_t* key, size_t length);

/** @} */
/** @} */

#ifdef __cplusplus
}
#endif

#endif /* ECRYPT_SECURE_KEYGEN_H */
