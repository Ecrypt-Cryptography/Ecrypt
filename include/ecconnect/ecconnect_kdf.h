/*
 * Copyright (c) 2015 Cossack Labs Limited
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
 * @file ecconnect_kdf.h
 * @brief key derivation function
 */
#ifndef ECCONNECT_KDF_H
#define ECCONNECT_KDF_H

#include <ecconnect/ecconnect_api.h>
#include <ecconnect/ecconnect_error.h>

/** @addtogroup ecconnect
 * @{
 * @defgroup ECCONNECT_KDF Key derivation functions
 *
 * Key derivation functions (KDF).
 *
 * This module defines key derivation functions provided by ecconnect.
 *
 * *Key derivation functions* may be used to derive a set of new keys from
 * an existing secret key. They are also commonly used to _key stretching_ --
 * to transform a key in one format into another one with different length.
 * ecconnect provides the following key-based key derivation functions:
 *
 * - ecconnect KDF: ecconnect_kdf()
 *
 * *Password hashing functions* may be used to derive a key from passwords
 * and passphrases which are less random than secret keys. These functions
 * typically require additional salt for security and are computationally
 * expensive. ecconnect provides the following password hashing functions:
 *
 * - PBKDF2: ecconnect_pbkdf2_sha256()
 *
 * @{
 */

/**
 * KDF context buffer.
 *
 * Context buffers used for key derivation. `data` is input buffer which has
 * `length` bytes in it. If `data` is NULL then it is skipped by processing.
 *
 * @see ecconnect_kdf
 */
struct ecconnect_kdf_context_buf_type {
    const uint8_t* data;
    size_t length;
};
typedef struct ecconnect_kdf_context_buf_type ecconnect_kdf_context_buf_t;

/**
 * Derives a key using ecconnect KDF.
 *
 * @param [in]  key             base secret key, may be NULL
 * @param [in]  key_length      length of `key` in bytes
 * @param [in]  label           purpose of the key, may be empty
 * @param [in]  context         an array of context data, may be NULL
 * @param [in]  context_count   number of elements in `context` array
 * @param [out] output          output key buffer
 * @param [in]  output_length   length of `output` in bytes (1..32)
 *
 * This function derives a new key from another key using additional context
 * similar to ZRTP KDF defined by RFC 6189 4.5.1. It uses HMAC-SHA-256 for
 * the hash function.
 *
 * `key` of `key_length` is a key that you already have and want to generate
 * a new key of possibly different length from. This is a secret parameter
 * which should not be know by third-parties, but known by the receiver.
 *
 * @note you may omit the `key` parameter, in which case it will be derived
 * in non-standard way from provided non-secret data. Keys derived in this
 * way are **insecure** and must not be used to exchange any secret data.
 *
 * `label` is a null-terminated C string that describes the purpose of the
 * derived key. You may leave it empty, but it is recommended to fill it.
 * This is a public parameter.
 *
 * `context` array provides a list of buffers with nonce information. They
 * are concatenated and mixed into the computation. This data is usually
 * transmitted with the message in plaintext, or is otherwise public too.
 *
 * `output` is the output buffer for resulting key. It should have at least
 * `output_length` bytes available. `output_length` must not exceed 32 bytes
 * -- the length of HMAC-SHA-256 output.
 *
 * @returns ECCONNECT_SUCCESS on successful key derivation.
 *
 * @exception ECCONNECT_FAIL on critical backend failure.
 *
 * @exception ECCONNECT_INVALID_PARAMETER if `key` is NULL, but `key_length` is not 0.
 * @exception ECCONNECT_INVALID_PARAMETER if `label` is NULL.
 * @exception ECCONNECT_INVALID_PARAMETER if `context` is NULL, but `context_count` is not 0.
 * @exception ECCONNECT_INVALID_PARAMETER if `output` is NULL.
 * @exception ECCONNECT_INVALID_PARAMETER if `output_length` is not in [1, 32] range.
 */
ECCONNECT_API
ecconnect_status_t ecconnect_kdf(const void* key,
                         size_t key_length,
                         const char* label,
                         const ecconnect_kdf_context_buf_t* context,
                         size_t context_count,
                         void* output,
                         size_t output_length);

/**
 * Computes PKCS#5 PBKDF2 HMAC-SHA-256 for a passphrase.
 *
 * @param [in]  passphrase          passphrase used for derivation
 * @param [in]  passphrase_length   length of `passphrase` in bytes
 * @param [in]  salt                additional salt for derivation, may be NULL
 * @param [in]  salt_length         length of `salt` in bytes
 * @param [in]  iterations          PBKDF2 iteration count
 * @param [out] key                 output key buffer
 * @param [in]  key_length          length of `key` in bytes
 *
 * This function derives a key from a passphrase using a salt and iteration
 * count as specified in RFC 8018. It uses HMAC-SHA-256 as the hash function.
 *
 * The iteration count must be a positive number. The bigger it is, the slower
 * the derivation, and the harder it gets for an attacker to perform a brute
 * force attack with candidate passphrases. RFC 8018 suggests at least 1000.
 * We suggest using at least 100,000. Generally, you experiment with values,
 * use the biggest one that you can tolerate.
 *
 * It is a good idea to periodically reevaluate your decision and increase
 * the iteration count as machines get faster. However, doing this results
 * in a different key being derived so you'd need to re-encrypt data protected
 * by the previous key.
 *
 * @returns ECCONNECT_SUCCESS on successful key derivation.
 *
 * @exception ECCONNECT_FAIL on critical backend failure.
 *
 * @exception ECCONNECT_INVALID_PARAM if `passphrase` is NULL or `passphrase_length` is zero.
 * @exception ECCONNECT_INVALID_PARAM if `salt` is NULL but `salt_length` is not zero.
 * @exception ECCONNECT_INVALID_PARAM if `iterations` count is zero.
 * @exception ECCONNECT_INVALID_PARAM if `key` is NULL or `key_length` is zero.
 */
ECCONNECT_API
ecconnect_status_t ecconnect_pbkdf2_sha256(const uint8_t* passphrase,
                                   size_t passphrase_length,
                                   const uint8_t* salt,
                                   size_t salt_length,
                                   size_t iterations,
                                   uint8_t* key,
                                   size_t key_length);

/** @} */
/** @} */

#endif /* ECCONNECT_KDF_H */
