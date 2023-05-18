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

#ifndef ECRYPT_SECURE_MESSAGE_WRAPPER_H
#define ECRYPT_SECURE_MESSAGE_WRAPPER_H

#include <ecconnect/ecconnect.h>

#include <ecrypt/ecrypt_error.h>

#define ECRYPT_SECURE_MESSAGE 0x26040000

#define ECRYPT_SECURE_MESSAGE_SIGNED (ECRYPT_SECURE_MESSAGE ^ 0x00002600)
#define ECRYPT_SECURE_MESSAGE_RSA_SIGNED (ECRYPT_SECURE_MESSAGE_SIGNED ^ 0x00000010)
#define ECRYPT_SECURE_MESSAGE_EC_SIGNED (ECRYPT_SECURE_MESSAGE_SIGNED ^ 0x00000020)

#define IS_ECRYPT_SECURE_MESSAGE_SIGNED(tag) \
    (((tag)&0xffffff00) == ECRYPT_SECURE_MESSAGE_SIGNED ? true : false)

#define ECRYPT_SECURE_MESSAGE_ENCRYPTED (ECRYPT_SECURE_MESSAGE ^ 0x00002700)
#define ECRYPT_SECURE_MESSAGE_RSA_ENCRYPTED (ECRYPT_SECURE_MESSAGE_ENCRYPTED ^ 0x00000010)
#define ECRYPT_SECURE_MESSAGE_EC_ENCRYPTED (ECRYPT_SECURE_MESSAGE_ENCRYPTED ^ 0x00000020)

#define IS_ECRYPT_SECURE_MESSAGE_ENCRYPTED(tag) \
    (((tag)&0xffffff00) == ECRYPT_SECURE_MESSAGE_ENCRYPTED ? true : false)

struct ecrypt_secure_message_hdr_type {
    uint32_t message_type;
    uint32_t message_length;
};
typedef struct ecrypt_secure_message_hdr_type ecrypt_secure_message_hdr_t;

struct ecrypt_secure_signed_message_hdr_type {
    ecrypt_secure_message_hdr_t message_hdr;
    uint32_t signature_length;
};

typedef struct ecrypt_secure_signed_message_hdr_type ecrypt_secure_signed_message_hdr_t;

typedef struct ecrypt_secure_encrypted_message_hdr_type {
    ecrypt_secure_message_hdr_t message_hdr;
} ecrypt_secure_encrypted_message_hdr_t;

struct ecrypt_secure_message_sign_worker_type {
    ecconnect_sign_ctx_t* sign_ctx;
};

typedef struct ecrypt_secure_message_sign_worker_type ecrypt_secure_message_signer_t;

ecrypt_secure_message_signer_t* ecrypt_secure_message_signer_init(const uint8_t* key, size_t key_length);
ecrypt_status_t ecrypt_secure_message_signer_proceed(ecrypt_secure_message_signer_t* ctx,
                                                     const uint8_t* message,
                                                     size_t message_length,
                                                     uint8_t* wrapped_message,
                                                     size_t* wrapped_message_length);
ecrypt_status_t ecrypt_secure_message_signer_destroy(ecrypt_secure_message_signer_t* ctx);

struct ecrypt_secure_message_verify_worker_type {
    ecconnect_verify_ctx_t* verify_ctx;
};
typedef struct ecrypt_secure_message_verify_worker_type ecrypt_secure_message_verifier_t;

ecrypt_secure_message_verifier_t* ecrypt_secure_message_verifier_init(const uint8_t* key,
                                                                      size_t key_length);
ecrypt_status_t ecrypt_secure_message_verifier_proceed(ecrypt_secure_message_verifier_t* ctx,
                                                       const uint8_t* wrapped_message,
                                                       size_t wrapped_message_length,
                                                       uint8_t* message,
                                                       size_t* message_length);
ecrypt_status_t ecrypt_secure_message_verifier_destroy(ecrypt_secure_message_verifier_t* ctx);

struct ecrypt_secure_message_encrypt_worker_type;

typedef struct ecrypt_secure_message_encrypt_worker_type ecrypt_secure_message_encrypter_t;

ecrypt_secure_message_encrypter_t* ecrypt_secure_message_encrypter_init(const uint8_t* private_key,
                                                                        size_t private_key_length,
                                                                        const uint8_t* peer_public_key,
                                                                        size_t peer_public_key_length);
ecrypt_status_t ecrypt_secure_message_encrypter_proceed(ecrypt_secure_message_encrypter_t* ctx,
                                                        const uint8_t* message,
                                                        size_t message_length,
                                                        uint8_t* wrapped_message,
                                                        size_t* wrapped_message_length);
ecrypt_status_t ecrypt_secure_message_encrypter_destroy(ecrypt_secure_message_encrypter_t* ctx);

typedef struct ecrypt_secure_message_encrypt_worker_type ecrypt_secure_message_decrypter_t;

ecrypt_secure_message_decrypter_t* ecrypt_secure_message_decrypter_init(const uint8_t* private_key,
                                                                        size_t private_key_length,
                                                                        const uint8_t* peer_public_key,
                                                                        size_t peer_public_key_length);
ecrypt_status_t ecrypt_secure_message_decrypter_proceed(ecrypt_secure_message_decrypter_t* ctx,
                                                        const uint8_t* message,
                                                        size_t message_length,
                                                        uint8_t* wrapped_message,
                                                        size_t* wrapped_message_length);
ecrypt_status_t ecrypt_secure_message_decrypter_destroy(ecrypt_secure_message_decrypter_t* ctx);

#endif /* ECRYPT_SECURE_MESSAGE_WRAPPER_H */
