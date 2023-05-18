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
 * @file ecconnect_asym_cipher.h
 * @brief asymmetric encryption/decryption routines
 */
#ifndef ECCONNECT_ASYM_CIPHER_H
#define ECCONNECT_ASYM_CIPHER_H

#include <ecconnect/ecconnect_api.h>
#include <ecconnect/ecconnect_error.h>

/**
 * @addtogroup ecconnect
 * @{
 * @defgroup ECCONNECT_ASYM_CIPHER asymmetric encryption/decryption routines
 * @brief asymmetric encryption/decryption routines
 * @{
 */

/**
 * @brief supported padding algorithms
 */
enum ecconnect_asym_cipher_padding_type {
    ECCONNECT_ASYM_CIPHER_NOPAD, /**< no padding */
    ECCONNECT_ASYM_CIPHER_OAEP   /**< oaep padding */
};

/** @brief padding algorithm typedef  */
typedef enum ecconnect_asym_cipher_padding_type ecconnect_asym_cipher_padding_t;

/** @brief assymetric encoding/decoding context typedef */
typedef struct ecconnect_asym_cipher_type ecconnect_asym_cipher_t;

/**
 * @brief create asymmetric encryption/decryption context
 * @param [in] key cipher key. If key point to public key ecconnect_asym_cipher_create return pointer to
 * encrypter object. Otherwise will return pointer to decrypter object.
 * @param [in] key_length length of key
 * @param [in] pad padding algorithm to be used. See @ref ecconnect_asym_cipher_padding_type
 * @return pointer to created asymmetric encryption/decryption context on success or NULL on failure
 */
ECCONNECT_API
ecconnect_asym_cipher_t* ecconnect_asym_cipher_create(const void* key,
                                              size_t key_length,
                                              ecconnect_asym_cipher_padding_t pad);

/**
 * @brief encrypt data
 * @param [in] asym_cipher_ctx pointer to asymmetric encryption/decryption context previously
 * created by ecconnect_asym_cipher_create
 * @param [in] plain_data data to encrypt
 * @param [in] plain_data_length length of plain_data
 * @param [out] cipher_data buffer for cipher data store. May be set to NULL for cipher data length
 * determination
 * @param [in, out] cipher_data_length length of cipher_data
 * @return result of operation, @ref ECCONNECT_SUCCESS on success or @ref ECCONNECT_FAIL on failure
 * @note If cipher_data==NULL or cipher_data_length less than needed to store cipher data, @ref
 * ECCONNECT_BUFFER_TOO_SMALL will return and cipher_data_length will contain length of buffer needed
 * to store cipher data.
 */
ECCONNECT_API
ecconnect_status_t ecconnect_asym_cipher_encrypt(ecconnect_asym_cipher_t* asym_cipher_ctx,
                                         const void* plain_data,
                                         size_t plain_data_length,
                                         void* cipher_data,
                                         size_t* cipher_data_length);

/**
 * @brief decrypt data
 * @param [in] asym_cipher_ctx pointer to asymmetric encryption/decryption context previously
 * created by ecconnect_asym_cipher_create
 * @param [in] cipher_data data to decrypt
 * @param [in] cipher_data_length length of cipher_data
 * @param [out] plain_data buffer for plain data store. May be set to NULL for plain data length
 * determination
 * @param [in, out] plain_data_length length of plain_data
 * @return result of operation, @ref ECCONNECT_SUCCESS on success or @ref ECCONNECT_FAIL on failure
 * @note If plain_data==NULL or plain_data_length less than needed to store plain data, @ref
 * ECCONNECT_BUFFER_TOO_SMALL will return and plain_data_length will contain length of buffer needed
 * to store plain data.
 */
ECCONNECT_API
ecconnect_status_t ecconnect_asym_cipher_decrypt(ecconnect_asym_cipher_t* asym_cipher_ctx,
                                         const void* cipher_data,
                                         size_t cipher_data_length,
                                         void* plain_data,
                                         size_t* plain_data_length);

/**
 * @brief import key to asymmetric encryption/decryption context
 * @param [in] asym_cipher_ctx pointer to asymmetric encryption/decryption context previously
 * created by ecconnect_asym_cipher_create
 * @param [in] key buffer with stored key
 * @param [in] key_length length of key
 * @return result of operation, @ref ECCONNECT_SUCCESS on success or @ref ECCONNECT_FAIL on failure
 */
// ecconnect_status_t ecconnect_asym_cipher_import_key(ecconnect_asym_cipher_t* asym_cipher_ctx, const void*
// key, size_t key_length);

/**
 * @brief destroy asymmetric encryption/decryption context
 * @param [in] asym_cipher_ctx pointer to asymmetric encryption/decryption context previously
 * created by ecconnect_asym_cipher_create
 * @return result of operation, @ref ECCONNECT_SUCCESS on success or @ref ECCONNECT_FAIL on failure
 */
ECCONNECT_API
ecconnect_status_t ecconnect_asym_cipher_destroy(ecconnect_asym_cipher_t* asym_cipher_ctx);

/** @} */
/** @} */

#endif /* ECCONNECT_ASYM_CIPHER_H */
