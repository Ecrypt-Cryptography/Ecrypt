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
 * @file ecconnect_hmac.h
 * @brief HMAC calculation routines
 */
#ifndef ECCONNECT_HMAC_H
#define ECCONNECT_HMAC_H

#include <ecconnect/ecconnect_api.h>
#include <ecconnect/ecconnect_error.h>
#include <ecconnect/ecconnect_hash.h>

/**
 * @addtogroup ecconnect
 * @{
 * @defgroup ECCONNECT_HMAC HMAC
 * @brief HMAC calculation routines
 * @details Usage example:
 * @code
 * #include <ecconnect/ecconnect.h>
 * ...
 * uint8_t data[data_length];
 * uint8_t *hmac=NULL;
 * size_t hmac_length;
 * ecconnect_hmac_ctx_t* ctx=ecconnect_hmac_create(ECCONNECT_HASH_SHA512);
 * if(ctx){
 *	ecconnect_status_t res=ecconnect_hmac_update(ctx, data, data_length);
 *	if(res==ECCONNECT_SUCCESS){
 *		res=ecconnect_hmac_final(ctx, NULL, &hmac_length);
 *		if(res==ECCONNECT_BUFFER_TOO_SMALL){
 *			hmac=malloc(hmac_length);
 *			if(hmac){
 *				res=ecconnect_hmac_final(ctx, hash, &hash_length);
 *				if(res==ECCONNECT_SUCCESS){
 *					//output hmac
 *				}
 *				free(hmac);
 *			}
 *		}
 *	}
 *	ecconnect_hmac_destroy(ctx);
 * }
 * @endcode
 * @{
 *
 */

/**
 * @typedef ecconnect_hmac_ctx_t
 * @brief  HMAC context typedef
 */
typedef struct ecconnect_hmac_ctx_type ecconnect_hmac_ctx_t;

/**
 * @brief creating of HMAC context
 * @param [in] algo hash algorithm to be used; see @ref ecconnect_hash_algo_type
 * @return pointer to HMAC context on success and  NULL on failure
 */
ECCONNECT_API
ecconnect_hmac_ctx_t* ecconnect_hmac_create(ecconnect_hash_algo_t algo, const uint8_t* key, size_t key_length);

/**
 * @brief destroy HMAC context
 * @param [in] hmac_ctx pointer to HMAC context previously created by @ref ecconnect_hmac_create
 * @return result of operation, @ref ECCONNECT_SUCCESS on success and @ref ECCONNECT_FAIL on failure
 */
ECCONNECT_API
ecconnect_status_t ecconnect_hmac_destroy(ecconnect_hmac_ctx_t* hmac_ctx);

/**
 * @brief update HMAC context with data
 * @param [in] hmac_ctx pointer to HMAC context previously created by @ref ecconnect_hmac_create
 * @param [in] data pointer to buffer with data to HMAC update
 * @param [in] length of data buffer
 * @return result of operation, @ref ECCONNECT_SUCCESS on success and @ref ECCONNECT_FAIL on failure
 */
ECCONNECT_API
ecconnect_status_t ecconnect_hmac_update(ecconnect_hmac_ctx_t* hmac_ctx, const void* data, size_t length);

/**
 * @brief final HMAC context and get hash value
 * @param [in] hmac_ctx pointer to hash context previously created by @ref ecconnect_hmac_create
 * @param [out] hmac_value pointer to buffer for HMAC value retrieve, may be set to NULL for HMAC
 * value length determination
 * @param [in, out] hmac_length length of hmac_value buffer
 * @return result of operation, @ref ECCONNECT_SUCCESS on success and @ref ECCONNECT_FAIL on failure.
 * @note If hmac_value==NULL or hmac_length less than needed to store HMAC value, @ref
 * ECCONNECT_BUFFER_TOO_SMALL will return and hmac_length will contain length of buffer thet need to
 * store HMAC value.
 */
ECCONNECT_API
ecconnect_status_t ecconnect_hmac_final(ecconnect_hmac_ctx_t* hmac_ctx, uint8_t* hmac_value, size_t* hmac_length);

/**@}@}*/

#endif /* ECCONNECT_HMAC_H */
