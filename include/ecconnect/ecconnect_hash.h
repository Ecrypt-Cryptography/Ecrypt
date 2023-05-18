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
 * @file ecconnect_hash.h
 * @brief routines for hash calculation
 */

#ifndef ECCONNECT_HASH_H
#define ECCONNECT_HASH_H

#include <ecconnect/ecconnect_api.h>
#include <ecconnect/ecconnect_error.h>

/**
 * @addtogroup ecconnect
 * @{
 * @defgroup HASH hash
 * @brief Hash calculation routines
 * @details Usage example:
 * @code
 * #include <ecconnect/ecconnect.h>
 * ...
 * uint8_t data[data_length];
 * uint8_t *hash=NULL;
 * size_t hash_length;
 * ecconnect_hash_ctx_t* ctx=ecconnect_hash_create(ECCONNECT_HASH_SHA512);
 * if(ctx){
 *	ecconnect_status_t res=ecconnect_hash_update(ctx, data, data_length);
 *	if(res==ECCONNECT_SUCCESS){
 *		res=ecconnect_hash_final(ctx, NULL, &hash_length);
 *		if(res==ECCONNECT_BUFFER_TOO_SMALL){
 *			hash=malloc(hash_length);
 *			if(hash){
 *				res=ecconnect_hash_final(ctx, hash, &hash_length);
 *				if(res==ECCONNECT_SUCCESS){
 *					//output hash
 *				}
 *				free(hash);
 *			}
 *		}
 *	}
 *	ecconnect_hash_destroy(ctx);
 * }
 * @endcode
 * @{
 */

/**
 * @enum ecconnect_hash_algo_type
 * @brief Supported hash algorithms
 */
enum ecconnect_hash_algo_type {
    //	ECCONNECT_HASH_SHA1,    /**< sha1   */
    ECCONNECT_HASH_SHA256, /**< sha256 */
    ECCONNECT_HASH_SHA512, /**< sha512 */
};

/**
 * @brief hash algorithm typedef
 */
typedef enum ecconnect_hash_algo_type ecconnect_hash_algo_t;

/**
 * @typedef ecconnect_hash_ctx_t
 * @brief hash context typedef
 */
typedef struct ecconnect_hash_ctx_type ecconnect_hash_ctx_t;

/**
 * @brief creating of hash context
 * @param [in] algo hash algorithm to be used; see @ref ecconnect_hash_algo_type
 * @return pointer to hash context on success and  NULL on failure
 */
ECCONNECT_API
ecconnect_hash_ctx_t* ecconnect_hash_create(ecconnect_hash_algo_t algo);

/**
 * @brief destroy hash context
 * @param [in] hash_ctx pointer to hash context previously created by @ref ecconnect_hash_create
 * @return result of operation, @ref ECCONNECT_SUCCESS on success and @ref ECCONNECT_FAIL on failure
 */
ECCONNECT_API
ecconnect_status_t ecconnect_hash_destroy(ecconnect_hash_ctx_t* hash_ctx);

ECCONNECT_API
ecconnect_status_t ecconnect_hash_cleanup(ecconnect_hash_ctx_t* hash_ctx);

/**
 * @brief update hash context with data
 * @param [in] hash_ctx pointer to hash context previously created by @ref ecconnect_hash_create
 * @param [in] data pointer to buffer with data to hash update
 * @param [in] length of data buffer
 * @return result of operation, @ref ECCONNECT_SUCCESS on success and @ref ECCONNECT_FAIL on failure
 */
ECCONNECT_API
ecconnect_status_t ecconnect_hash_update(ecconnect_hash_ctx_t* hash_ctx, const void* data, size_t length);

/**
 * @brief final hash context and get hash value
 * @param [in] hash_ctx pointer to hash context previously created by @ref ecconnect_hash_create
 * @param [out] hash_value pointer to buffer for hash value retrieve, may be set to NULL for hash
 * value length determination
 * @param [in, out] hash_length length of hash_value buffer
 * @return result of operation, @ref ECCONNECT_SUCCESS on success and @ref ECCONNECT_FAIL on failure.
 * @note If hash_value==NULL or hash_length less than needed to store hash value, @ref
 * ECCONNECT_BUFFER_TOO_SMALL will return and hash_length will contain length of buffer thet need to
 * store hash value.
 */
ECCONNECT_API
ecconnect_status_t ecconnect_hash_final(ecconnect_hash_ctx_t* hash_ctx, uint8_t* hash_value, size_t* hash_length);

/**@}@}*/

#endif /* ECCONNECT_HASH_H */
