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
 * @file ecconnect_asym_ka.h
 * @brief asymmetric key agreement routines
 */
#ifndef ECCONNECT_ASYM_KA_H
#define ECCONNECT_ASYM_KA_H

#include <ecconnect/ecconnect_api.h>
#include <ecconnect/ecconnect_error.h>

/** @addtogroup ecconnect
 * @{
 * @defgroup ECCONNECT_ASYM_KA asymmetric key agreement routines
 * @brief asymmetric key agreement routines
 * @{
 */

/** @brief supported key agreement algorithms */
enum ecconnect_asym_ka_alg_type {
    ECCONNECT_ASYM_KA_EC_P256 /**< elliptic curve 256 */
};

/** @brief key agreement algorithms typedef */
typedef enum ecconnect_asym_ka_alg_type ecconnect_asym_ka_alg_t;

/** @brief key agreement context typedef */
typedef struct ecconnect_asym_ka_type ecconnect_asym_ka_t;

/** @brief create key agreement context
 * @param [in] alg algorithm to use. See @ref ecconnect_asym_ka_alg_type
 * @return pointer to created key agreement context on success or NULL on failure
 */
ECCONNECT_API
ecconnect_asym_ka_t* ecconnect_asym_ka_create(ecconnect_asym_ka_alg_t alg);

/**
 * @brief asymmetric keys pair generation for key agreement context
 * @param [in] asym_ka_ctx pointer to key agreement context previously created by
 * ecconnect_asym_ka_create
 * @return result of operation, @ref ECCONNECT_SUCCESS on success or @ref ECCONNECT_FAIL on failure
 */
ECCONNECT_API
ecconnect_status_t ecconnect_asym_ka_gen_key(ecconnect_asym_ka_t* asym_ka_ctx);

/**
 * @brief export key from key agreement context
 * @param [in] asym_ka_ctx pointer to key agreement context previously created by
 * ecconnect_asym_ka_create
 * @param [out] key buffer to store exported key
 * @param [in,out] key_length length of key. May be set to NULL for key length determination
 * @param [in] isprivate if set private key will be exported. If not set public key will be exported
 * @return result of operation, @ref  ECCONNECT_SUCCESS on success or @ref ECCONNECT_FAIL on failure
 * @note If key==NULL or key_length less than needed to store key, @ref ECCONNECT_BUFFER_TOO_SMALL will
 * return and key_length will contain length of buffer needed to store key.
 */
ECCONNECT_API
ecconnect_status_t ecconnect_asym_ka_export_key(ecconnect_asym_ka_t* asym_ka_ctx,
                                        void* key,
                                        size_t* key_length,
                                        bool isprivate);

/**
 * @brief import key to key agreement context
 * @param [in] asym_ka_ctx pointer to key agreement context previously created by
 * ecconnect_asym_ka_create
 * @param [in] key buffer with stored key
 * @param [in] key_length length of key
 * @return result of operation, @ref ECCONNECT_SUCCESS on success or @ref ECCONNECT_FAIL on failure
 */
ECCONNECT_API
ecconnect_status_t ecconnect_asym_ka_import_key(ecconnect_asym_ka_t* asym_ka_ctx, const void* key, size_t key_length);

/**
 * @brief derive shared secret from key agreement context
 * @param [in] asym_ka_ctx pointer to key agreement context previously created by
 * ecconnect_asym_ka_create
 * @param [in] peer_key buffer with peer public key
 * @param [in] peer_key_length length of peer_key
 * @param [out] shared_secret buffer to store shared secret. May be set to NULL for shared secret
 * length determination
 * @param [in,out] shared_secret_length length of shared secret
 * @return result of operation, @ref ECCONNECT_SUCCESS on success or @ref ECCONNECT_FAIL on failure
 * @note If shared_secret==NULL or shared_secret_length less than needed to store shared secret, @ref
 * ECCONNECT_BUFFER_TOO_SMALL will return and shared_secret_length will contain length of buffer needed
 * to store shared secret.
 */
ECCONNECT_API
ecconnect_status_t ecconnect_asym_ka_derive(ecconnect_asym_ka_t* asym_ka_ctx,
                                    const void* peer_key,
                                    size_t peer_key_length,
                                    void* shared_secret,
                                    size_t* shared_secret_length);

/**
 * @brief destroy key agreement context
 * @param [in] asym_ka_ctx pointer to key agreement context previously created by
 * ecconnect_asym_ka_create
 * @return result of operation, @ref ECCONNECT_SUCCESS on success or @ref ECCONNECT_FAIL on failure
 */
ECCONNECT_API
ecconnect_status_t ecconnect_asym_ka_destroy(ecconnect_asym_ka_t* asym_ka_ctx);

/** @} */
/** @} */

#endif /* ECCONNECT_ASYM_KA_H */
