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

#ifndef ECCONNECT_T_H
#define ECCONNECT_T_H

#include <ecconnect/ecconnect_asym_cipher.h>
#include <ecconnect/ecconnect_asym_ka.h>
#include <ecconnect/ecconnect_asym_sign.h>
#include <ecconnect/ecconnect_error.h>
#include <ecconnect/ecconnect_hash.h>
#include <ecconnect/ecconnect_hmac.h>

#ifdef CRYPTO_ENGINE_PATH
// NOLINTNEXTLINE(bugprone-macro-parentheses): preprocessor wizardry
#define CEP <ecconnect/CRYPTO_ENGINE_PATH/ecconnect_engine.h>
#include CEP
#undef CEP
#else
#include <ecconnect/openssl/ecconnect_engine.h>
#endif

ecconnect_status_t ecconnect_hash_init(ecconnect_hash_ctx_t* hash_ctx, ecconnect_hash_algo_t algo);

ecconnect_status_t ecconnect_asym_cipher_init(ecconnect_asym_cipher_t* asym_cipher,
                                      const void* key,
                                      size_t key_length,
                                      ecconnect_asym_cipher_padding_t pad);
ecconnect_status_t ecconnect_asym_cipher_cleanup(ecconnect_asym_cipher_t* asym_cipher);

ecconnect_status_t ecconnect_asym_ka_init(ecconnect_asym_ka_t* asym_ka_ctx, ecconnect_asym_ka_alg_t alg);
ecconnect_status_t ecconnect_asym_ka_cleanup(ecconnect_asym_ka_t* asym_ka_ctx);

ecconnect_status_t ecconnect_sign_init(ecconnect_sign_ctx_t* ctx,
                               ecconnect_sign_alg_t algId,
                               const void* private_key,
                               size_t private_key_length,
                               const void* public_key,
                               size_t public_key_length);
ecconnect_status_t ecconnect_verify_init(ecconnect_sign_ctx_t* ctx,
                                 ecconnect_sign_alg_t algId,
                                 const void* private_key,
                                 size_t private_key_length,
                                 const void* public_key,
                                 size_t public_key_length);

/* Largest possible block size for supported hash functions (SHA-512) */
#define HASH_MAX_BLOCK_SIZE 128

struct ecconnect_hmac_ctx_type {
    uint8_t o_key_pad[HASH_MAX_BLOCK_SIZE];
    size_t block_size;
    ecconnect_hash_algo_t algo;
    ecconnect_hash_ctx_t* hash_ctx;
};

ECCONNECT_PRIVATE_API
ecconnect_status_t ecconnect_hmac_init(ecconnect_hmac_ctx_t* hmac_ctx,
                               ecconnect_hash_algo_t algo,
                               const uint8_t* key,
                               size_t key_length);
ECCONNECT_PRIVATE_API
ecconnect_status_t ecconnect_hmac_cleanup(ecconnect_hmac_ctx_t* hmac_ctx);

#endif /* ECCONNECT_T_H */
