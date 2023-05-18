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
 * @file ecconnect_sym.h
 * @brief symmetric encryption/decryption routines
 */

#ifndef ECCONNECT_SYM_H
#define ECCONNECT_SYM_H

#include <ecconnect/ecconnect_api.h>
#include <ecconnect/ecconnect_error.h>

/**
 * @addtogroup ecconnect
 * @{
 * @defgroup ECCONNECT_SYM symmetric encryption/decryption routines
 * @brief symmetric encryption/decryption routines
 * @{
 * @defgroup ECCONNECT_SYM_ALGORITHMS symmetric encryption/decryption  algorithms
 * @brief supported symmetric encryption/decryption algorithms definitions
 * @details Algorithm definition example:
 * @code
 * ECCONNECT_SYM_AES_GCM|ECCONNECT_SYM_NOKDF|ECCONNECT_SYM_256_KEY_LENGTH  //AES in GCM mode with 256 bits key
 * length without kdf ECCONNECT_SYM_AES_CTR|ECCONNECT_SYM_PBKDF2|ECCONNECT_SYM_128_KEY_LENGTH //AES in CTR mode
 * with 128 bits key length with pbkdf2
 * @endcode
 * @{
 *
 * @defgroup ECCONNECT_SYM_ALGORITHMS_IDS symmetric encryption/decryption  algorithms ids
 * @brief supported symmetric encryption/decryption algorithms definitions
 * @{
 */

/** AES in ECB mode with pkcs7 padding */
#define ECCONNECT_SYM_AES_ECB_PKCS7 0x10010000
/** AES in CTR mode */
#define ECCONNECT_SYM_AES_CTR 0x20000000
/** AES in XTS mode */
#define ECCONNECT_SYM_AES_XTS 0x30000000
/** AES in GCM mode (with authenticated encryption) */
#define ECCONNECT_SYM_AES_GCM 0x40010000

/** @} */

/**
 * @defgroup ECCONNECT_KDF_ALGS kdf algorithms
 * @brief supported kdf algorithms
 * @{
 */
/** do not use kdf */
#define ECCONNECT_SYM_NOKDF 0x00000000
/** pbkdf2 algorithm */
#define ECCONNECT_SYM_PBKDF2 0x01000000
/** @} */

/**
 * @defgroup ECCONNECT_KEY_LENGTH supported lengths of keys
 * @brief supported lengths of keys
 * @{
 */
/** 256 bits */
#define ECCONNECT_SYM_256_KEY_LENGTH 0x00000100
/** 192 bits */
#define ECCONNECT_SYM_192_KEY_LENGTH 0x000000c0
/** 512 bits */
#define ECCONNECT_SYM_128_KEY_LENGTH 0x00000080

/** @} */

/**
 * @defgroup ECCONNECT_SYM_MASK masks definition for symmetric algorithm id
 * @brief masks definition for symmetric algorithm id
 * @{
 */
/** key length mask */
#define ECCONNECT_SYM_KEY_LENGTH_MASK 0x00000fff
/** padding algorithm */
#define ECCONNECT_SYM_PADDING_MASK 0x000f0000
/** encryption algorithm */
#define ECCONNECT_SYM_ALG_MASK 0xf0000000
/** kdf algorithm */
#define ECCONNECT_SYM_KDF_MASK 0x0f000000

/** @} */
/** @} */

/**
 * @defgroup ECCONNECT_SYM_ROUTINES symmetric encryption/decryption routines
 * @brief symmetric encryption/decryption routines
 * @{
 */

/** @brief symmetric context typedef */
typedef struct ecconnect_sym_ctx_type ecconnect_sym_ctx_t;

/**
 * @defgroup ECCONNECT_SYM_ROUTINES_NOAUTH without authenticated encryption
 * @brief symmetric encryption/decryption without authenticated encryption
 * @{
 */
/**
 * @defgroup ECCONNECT_SYM_ROUTINES_NOAUTH_ENCRYPT encryption
 * @brief symmetric encryption without authenticated encryption
 * @{
 */

/**
 * @brief create symmetric encryption context
 * @param [in] alg algorithm id for usage. See @ref ECCONNECT_SYM_ALGORITHMS
 * @param [in] key pointer to key buffer
 * @param [in] key_length length of key
 * @param [in] salt pointer to salt buffer
 * @param [in] salt_length length of salt
 * @param [in] iv pointer to iv buffer
 * @param [in] iv_length length of iv
 * @return pointer to new symmetric encryption context on success or NULL on failure
 */
ECCONNECT_API
ecconnect_sym_ctx_t* ecconnect_sym_encrypt_create(uint32_t alg,
                                          const void* key,
                                          size_t key_length,
                                          const void* salt,
                                          size_t salt_length,
                                          const void* iv,
                                          size_t iv_length);

/**
 * @brief update symmetric encryption context
 * @param [in] ctx pointer to symmetric encryption context previously created by
 * ecconnect_sym_encrypt_create
 * @param [in] plain_data pointer to data buffer to encrypt
 * @param [in] data_length length of plain_data
 * @param [out] cipher_data pointer to buffer to cipher data store, may be set to NULL for cipher
 * data length determination
 * @param [in, out] cipher_data_length length of cipher_data
 * @return result of operation, @ref ECCONNECT_SUCCESS on success and @ref ECCONNECT_FAIL on failure.
 * @note If cipher_data==NULL or cipher_data_length less than needed to store cipher data, @ref
 * ECCONNECT_BUFFER_TOO_SMALL will return and cipher_data_length will contain length of buffer needed
 * to store cipher data.
 */
ECCONNECT_API
ecconnect_status_t ecconnect_sym_encrypt_update(ecconnect_sym_ctx_t* ctx,
                                        const void* plain_data,
                                        size_t data_length,
                                        void* cipher_data,
                                        size_t* cipher_data_length);

/**
 * @brief final symmetric encryption context
 * @param [in] ctx pointer to symmetric encryption context previously created by
 * ecconnect_sym_encrypt_create
 * @param [out] cipher_data pointer to buffer to cipher data store, may be set to NULL for cipher
 * data length determination
 * @param [in, out] cipher_data_length length of cipher_data
 * @return result of operation, @ref ECCONNECT_SUCCESS on success and @ref ECCONNECT_FAIL on failure.
 * @note If cipher_data==NULL or cipher_data_length less than needed to store cipher data, @ref
 * ECCONNECT_BUFFER_TOO_SMALL will return and cipher_data_length will contain length of buffer needed
 * to store cipher data.
 */
ECCONNECT_API
ecconnect_status_t ecconnect_sym_encrypt_final(ecconnect_sym_ctx_t* ctx, void* cipher_data, size_t* cipher_data_length);

/**
 * @brief destroy symmetric encryption context
 * @param [in] ctx pointer to symmetric encryption context previously created by
 * ecconnect_sym_encrypt_create
 * @return result of operation, @ref ECCONNECT_SUCCESS on success and @ref ECCONNECT_FAIL on failure.
 */
ECCONNECT_API
ecconnect_status_t ecconnect_sym_encrypt_destroy(ecconnect_sym_ctx_t* ctx);
/** @} */

/**
 * @defgroup ECCONNECT_SYM_ROUTINES_NOAUTH_DECRYPT decryption
 * @brief symmetric decryption without authenticated encryption
 * @{
 */

/**
 * @brief create symmetric decryption context
 * @param [in] alg algorithm id for usage. See @ref ECCONNECT_SYM_ALGORITHMS
 * @param [in] key pointer to key buffer
 * @param [in] key_length length of key
 * @param [in] salt pointer to salt buffer
 * @param [in] salt_length length of salt
 * @param [in] iv pointer to iv buffer
 * @param [in] iv_length length of iv
 * @return pointer to new symmetric decryption context on success or NULL on failure
 */
ECCONNECT_API
ecconnect_sym_ctx_t* ecconnect_sym_decrypt_create(uint32_t alg,
                                          const void* key,
                                          size_t key_length,
                                          const void* salt,
                                          size_t salt_length,
                                          const void* iv,
                                          size_t iv_length);

/**
 * @brief update symmetric decryption context
 * @param [in] ctx pointer to symmetric decryption context previously created by
 * ecconnect_sym_decrypt_create
 * @param [in] cipher_data pointer to data buffer to decrypt
 * @param [in] data_length length of cipher_data
 * @param [out] plain_data pointer to buffer to plain data store, may be set to NULL for plain data
 * length determination
 * @param [in, out] plain_data_length length of plaintext data
 * @return result of operation, @ref ECCONNECT_SUCCESS on success and @ref ECCONNECT_FAIL on failure.
 * @note If plain_data==NULL or plain_data_length less than needed to store plain data, @ref
 * ECCONNECT_BUFFER_TOO_SMALL will return and plain_data_length will contain length of buffer needed
 * to store plain data.
 */
ECCONNECT_API
ecconnect_status_t ecconnect_sym_decrypt_update(ecconnect_sym_ctx_t* ctx,
                                        const void* cipher_data,
                                        size_t data_length,
                                        void* plain_data,
                                        size_t* plain_data_length);

/**
 * @brief final symmetric decryption context
 * @param [in] ctx pointer to symmetric decryption context previously created by
 * ecconnect_sym_decrypt_create
 * @param [out] plain_data pointer to buffer to plain data store, may be set to NULL for plain data
 * length determination
 * @param [in, out] plain_data_length length of plaintext data
 * @return result of operation, @ref ECCONNECT_SUCCESS on success and @ref ECCONNECT_FAIL on failure.
 * @note If plain_data==NULL or plain_data_length less than needed to store plain data, @ref
 * ECCONNECT_BUFFER_TOO_SMALL will return and plain_data_length will contain length of buffer needed
 * to store plain data.
 */
ECCONNECT_API
ecconnect_status_t ecconnect_sym_decrypt_final(ecconnect_sym_ctx_t* ctx, void* plain_data, size_t* plain_data_length);

/**
 * @brief destroy symmetric decryption context
 * @param [in] ctx pointer to symmetric decryption context previously created by
 * ecconnect_sym_decrypt_create
 * @return result of operation, @ref ECCONNECT_SUCCESS on success and @ref ECCONNECT_FAIL on failure.
 */
ECCONNECT_API
ecconnect_status_t ecconnect_sym_decrypt_destroy(ecconnect_sym_ctx_t* ctx);
/** @} */
/** @} */

/**
 * @defgroup ECCONNECT_SYM_ROUTINES_AUTH with authenticated encryption
 * @brief symmetric encryption/decryption with authenticated encryption
 * @{
 */

/**
 * @defgroup ECCONNECT_SYM_ROUTINES_AUTH_ENCRYPT encryption
 * @brief symmetric encryption with authenticated encryption
 * @{
 */

/**
 * @brief create symmetric encryption context
 * @param [in] alg algorithm id for usage. See @ref ECCONNECT_SYM_ALGORITHMS
 * @param [in] key pointer to key buffer
 * @param [in] key_length length of key
 * @param [in] salt pointer to salt buffer
 * @param [in] salt_length length of salt
 * @param [in] iv pointer to iv buffer
 * @param [in] iv_length length of iv
 * @return pointer to new symmetric encryption context on success or NULL on failure
 */
ECCONNECT_API
ecconnect_sym_ctx_t* ecconnect_sym_aead_encrypt_create(uint32_t alg,
                                               const void* key,
                                               size_t key_length,
                                               const void* salt,
                                               size_t salt_length,
                                               const void* iv,
                                               size_t iv_length);

/**
 * @brief Add AAD data to symmetric encryption context
 * @param [in] ctx pointer to symmetric encryption context previously created by
 * ecconnect_sym_encrypt_create
 * @param [in] plain_data pointer to buffer with AAD data
 * @param [in] data_length length of AAD data
 * @return result of operation, @ref ECCONNECT_SUCCESS on success and @ref ECCONNECT_FAIL on failure.
 */
ECCONNECT_API
ecconnect_status_t ecconnect_sym_aead_encrypt_aad(ecconnect_sym_ctx_t* ctx, const void* plain_data, size_t data_length);

/**
 * @brief update symmetric encryption context
 * @param [in] ctx pointer to symmetric encryption context previously created by
 * ecconnect_sym_encrypt_create
 * @param [in] plain_data pointer to data buffer to encrypt
 * @param [in] data_length length of plain_data
 * @param [out] cipher_data pointer to buffer to cipher data store, may be set to NULL for cipher
 * data length determination
 * @param [in, out] cipher_data_length  length of cipher data
 * @return result of operation, @ref ECCONNECT_SUCCESS on success and @ref ECCONNECT_FAIL on failure.
 * @note If cipher_data==NULL or cipher_data_length less than needed to store cipher data, @ref
 * ECCONNECT_BUFFER_TOO_SMALL will return and cipher_data_length will contain length of buffer needed
 * to store cipher data.
 */
ECCONNECT_API
ecconnect_status_t ecconnect_sym_aead_encrypt_update(ecconnect_sym_ctx_t* ctx,
                                             const void* plain_data,
                                             size_t data_length,
                                             void* cipher_data,
                                             size_t* cipher_data_length);

/**
 * Finalize symmetric encryption context.
 *
 * @param [in]  ctx       pointer to symmetric encryption context previously
 *                        created by ecconnect_sym_encrypt_create
 * @param [out] auth_tag  pointer to buffer for auth tag store,
 *                        may be set to NULL to query auth tag length
 * @param [in, out] auth_tag_length  length of auth_tag
 *
 * @return result of operation, @ref ECCONNECT_SUCCESS on success and @ref ECCONNECT_FAIL on failure.
 *
 * @note If auth_tag is NULL or auth_tag_length is not big enough to store an auth tag,
 *       @ref ECCONNECT_BUFFER_TOO_SMALL is returned and auth_tag_length will contain suitable
 *       size for the buffer that is required to store auth_tag.
 */
ECCONNECT_API
ecconnect_status_t ecconnect_sym_aead_encrypt_final(ecconnect_sym_ctx_t* ctx, void* auth_tag, size_t* auth_tag_length);

/**
 * @brief destroy symmetric encryption context
 * @param [in] ctx pointer to symmetric encryption context previously created by
 * ecconnect_sym_encrypt_create
 * @return result of operation, @ref ECCONNECT_SUCCESS on success and @ref ECCONNECT_FAIL on failure.
 */
ECCONNECT_API
ecconnect_status_t ecconnect_sym_aead_encrypt_destroy(ecconnect_sym_ctx_t* ctx);
/** @} */

/**
 * @defgroup ECCONNECT_SYM_ROUTINES_AUTH_DECRYPT decryption
 * @brief symmetric decryption with authenticated encryption
 * @{
 */

/**
 * @brief create symmetric decryption context
 * @param [in] alg algorithm id for usage. See @ref ECCONNECT_SYM_ALGORITHMS
 * @param [in] key pointer to key buffer
 * @param [in] key_length length of key
 * @param [in] salt pointer to salt buffer
 * @param [in] salt_length length of salt
 * @param [in] iv pointer to iv buffer
 * @param [in] iv_length length of iv
 * @return pointer to new symmetric decryption context on success or NULL on failure
 */
ECCONNECT_API
ecconnect_sym_ctx_t* ecconnect_sym_aead_decrypt_create(uint32_t alg,
                                               const void* key,
                                               size_t key_length,
                                               const void* salt,
                                               size_t salt_length,
                                               const void* iv,
                                               size_t iv_length);

/**
 * @brief Add AAD data to symmetric decryption context
 * @param [in] ctx pointer to symmetric decryption context previously created by
 * ecconnect_sym_decrypt_create
 * @param [in] plain_data pointer to buffer with AAD data
 * @param [in] data_length length of AAD data
 * @return result of operation, @ref ECCONNECT_SUCCESS on success and @ref ECCONNECT_FAIL on failure.
 */
ECCONNECT_API
ecconnect_status_t ecconnect_sym_aead_decrypt_aad(ecconnect_sym_ctx_t* ctx, const void* plain_data, size_t data_length);

/**
 * @brief update symmetric decryption context
 * @param [in] ctx pointer to symmetric decryption context previously created by
 * ecconnect_sym_decrypt_create
 * @param [in] cipher_data pointer to data buffer to decrypt
 * @param [in] data_length length of cipher_data
 * @param [out] plain_data pointer to buffer to plain data store, may be set to NULL for plain data
 * length determination
 * @param [in, out] plain_data_length length of plain_data
 * @return result of operation, @ref ECCONNECT_SUCCESS on success and @ref ECCONNECT_FAIL on failure.
 * @note If plain_data==NULL or plain_data_length less than needed to store plain data, @ref
 * ECCONNECT_BUFFER_TOO_SMALL will return and plain_data_length will contain length of buffer needed
 * to store plain data.
 */
ECCONNECT_API
ecconnect_status_t ecconnect_sym_aead_decrypt_update(ecconnect_sym_ctx_t* ctx,
                                             const void* cipher_data,
                                             size_t data_length,
                                             void* plain_data,
                                             size_t* plain_data_length);

/**
 * @brief final symmetric decryption context
 * @param [in] ctx pointer to symmetric decryption context previously created by
 * ecconnect_sym_decrypt_create
 * @param [in] auth_tag pointer to buffer of auth tag
 * @param [in] auth_tag_length length of auth_tag
 * @return result of operation, @ref ECCONNECT_SUCCESS on success and @ref ECCONNECT_FAIL on failure.
 */
ECCONNECT_API
ecconnect_status_t ecconnect_sym_aead_decrypt_final(ecconnect_sym_ctx_t* ctx,
                                            const void* auth_tag,
                                            size_t auth_tag_length);

/**
 * @brief destroy symmetric decryption context
 * @param [in] ctx pointer to symmetric decryption context previously created by
 * ecconnect_sym_decrypt_create
 * @return result of operation, @ref ECCONNECT_SUCCESS on success and @ref ECCONNECT_FAIL on failure.
 */
ECCONNECT_API
ecconnect_status_t ecconnect_sym_aead_decrypt_destroy(ecconnect_sym_ctx_t* ctx);
/** @} */
/** @} */
/** @} */

/** @}@} */

#endif /* ECCONNECT_SYM_H */
