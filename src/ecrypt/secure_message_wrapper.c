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

#include "ecrypt/secure_message_wrapper.h"

#include <string.h>

#include "ecconnect/ecconnect.h"
#include "ecconnect/ecconnect_ec_key.h"
#include "ecconnect/ecconnect_rsa_key.h"

#include "ecrypt/secure_cell.h"

#define ECRYPT_RSA_SYM_ALG (ECCONNECT_SYM_AES_CTR | ECCONNECT_SYM_256_KEY_LENGTH | ECCONNECT_SYM_PBKDF2)
#define ECRYPT_RSA_SYMM_PASSWD_LENGTH 70 //!!! need to approve
//#define ECRYPT_RSA_SYMM_ENCRYPTED_PASSWD_LENGTH 256 //encrypted password for rsa 256
#define ECRYPT_RSA_SYMM_SALT_LENGTH 16

#define ECRYPT_EC_SYM_ALG (ECCONNECT_SYM_AES_CTR | ECCONNECT_SYM_256_KEY_LENGTH | ECCONNECT_SYM_PBKDF2)

ecconnect_sign_alg_t get_alg_id(const uint8_t* key, size_t key_length)
{
    if (key_length < sizeof(ecconnect_container_hdr_t)
        && key_length < (size_t)((const ecconnect_container_hdr_t*)key)->size) {
        return (ecconnect_sign_alg_t)(-1);
    }
    if (memcmp(((const ecconnect_container_hdr_t*)key)->tag, EC_PRIV_KEY_PREF, 3) == 0
        || memcmp(((const ecconnect_container_hdr_t*)key)->tag, EC_PUB_KEY_PREF, 3) == 0) {
        return ECCONNECT_SIGN_ecdsa_none_pkcs8;
    }
    if (memcmp(((const ecconnect_container_hdr_t*)key)->tag, RSA_PRIV_KEY_PREF, 3) == 0
        || memcmp(((const ecconnect_container_hdr_t*)key)->tag, RSA_PUB_KEY_PREF, 3) == 0) {
        return ECCONNECT_SIGN_rsa_pss_pkcs8;
    }
    return ECCONNECT_SIGN_undefined;
}

ecrypt_secure_message_signer_t* ecrypt_secure_message_signer_init(const uint8_t* key,
                                                                  const size_t key_length)
{
    ecrypt_secure_message_signer_t* ctx = malloc(sizeof(ecrypt_secure_message_signer_t));
    if (!ctx) {
        return NULL;
    }
    ctx->sign_ctx = ecconnect_sign_create(get_alg_id(key, key_length), NULL, 0, key, key_length);
    if (!(ctx->sign_ctx)) {
        free(ctx);
        return NULL;
    }
    return ctx;
}

ecrypt_status_t ecrypt_secure_message_signer_proceed(ecrypt_secure_message_signer_t* ctx,
                                                     const uint8_t* message,
                                                     const size_t message_length,
                                                     uint8_t* wrapped_message,
                                                     size_t* wrapped_message_length)
{
    ECRYPT_CHECK(ctx != NULL && ctx->sign_ctx != NULL);
    ECRYPT_CHECK(message != NULL && message_length != 0 && wrapped_message_length != NULL);
    uint8_t* signature = NULL;
    size_t signature_length = 0;
    ECRYPT_CHECK(ecconnect_sign_update(ctx->sign_ctx, message, message_length) == ECRYPT_SUCCESS);
    ECRYPT_CHECK(ecconnect_sign_final(ctx->sign_ctx, signature, &signature_length)
                 == ECRYPT_BUFFER_TOO_SMALL);
    if (wrapped_message == NULL
        || (message_length + signature_length + sizeof(ecrypt_secure_signed_message_hdr_t)
            > (*wrapped_message_length))) {
        (*wrapped_message_length) = message_length + signature_length
                                    + sizeof(ecrypt_secure_signed_message_hdr_t);
        return ECRYPT_BUFFER_TOO_SMALL;
    }
    signature = malloc(signature_length);
    ECRYPT_CHECK(signature != NULL);
    if (ecconnect_sign_final(ctx->sign_ctx, signature, &signature_length) != ECRYPT_SUCCESS) {
        free(signature);
        return ECRYPT_FAIL;
    }
    ecrypt_secure_signed_message_hdr_t hdr;
    switch (ecconnect_sign_get_alg_id(ctx->sign_ctx)) {
    case ECCONNECT_SIGN_ecdsa_none_pkcs8:
        hdr.message_hdr.message_type = ECRYPT_SECURE_MESSAGE_EC_SIGNED;
        break;
    case ECCONNECT_SIGN_rsa_pss_pkcs8:
        hdr.message_hdr.message_type = ECRYPT_SECURE_MESSAGE_RSA_SIGNED;
        break;
    default:
        return ECRYPT_INVALID_PARAMETER;
    };
    hdr.message_hdr.message_length = (uint32_t)message_length;
    hdr.signature_length = (uint32_t)signature_length;
    memcpy(wrapped_message, &hdr, sizeof(ecrypt_secure_signed_message_hdr_t));
    memcpy(wrapped_message + sizeof(ecrypt_secure_signed_message_hdr_t), message, message_length);
    memcpy(wrapped_message + sizeof(ecrypt_secure_signed_message_hdr_t) + message_length,
           signature,
           signature_length);
    (*wrapped_message_length) = message_length + signature_length
                                + sizeof(ecrypt_secure_signed_message_hdr_t);
    free(signature);
    return ECRYPT_SUCCESS;
}

ecrypt_status_t ecrypt_secure_message_signer_destroy(ecrypt_secure_message_signer_t* ctx)
{
    ecconnect_sign_destroy(ctx->sign_ctx);
    free(ctx);
    return ECRYPT_SUCCESS;
}

ecrypt_secure_message_verifier_t* ecrypt_secure_message_verifier_init(const uint8_t* key,
                                                                      const size_t key_length)
{
    ecrypt_secure_message_verifier_t* ctx = malloc(sizeof(ecrypt_secure_message_verifier_t));
    if (!ctx) {
        return NULL;
    }
    ctx->verify_ctx = ecconnect_verify_create(get_alg_id(key, key_length), key, key_length, NULL, 0);
    if (!ctx->verify_ctx) {
        free(ctx);
        return NULL;
    }
    return ctx;
}

static inline uint64_t total_signed_message_length(const ecrypt_secure_signed_message_hdr_t* msg)
{
    /* We're using uint64_t to avoid overflows. Length components are uint32_t. */
    uint64_t length = sizeof(ecrypt_secure_signed_message_hdr_t);
    length += msg->message_hdr.message_length;
    length += msg->signature_length;
    return length;
}

ecrypt_status_t ecrypt_secure_message_verifier_proceed(ecrypt_secure_message_verifier_t* ctx,
                                                       const uint8_t* wrapped_message,
                                                       const size_t wrapped_message_length,
                                                       uint8_t* message,
                                                       size_t* message_length)
{
    ECRYPT_CHECK(ctx != NULL);
    ECRYPT_CHECK(wrapped_message != NULL)
    ECRYPT_CHECK(wrapped_message_length >= sizeof(ecrypt_secure_signed_message_hdr_t));
    ECRYPT_CHECK(message_length != NULL);
    ecrypt_secure_signed_message_hdr_t* msg = (ecrypt_secure_signed_message_hdr_t*)wrapped_message;
    if (msg->message_hdr.message_type == ECRYPT_SECURE_MESSAGE_RSA_SIGNED
        && ecconnect_verify_get_alg_id(ctx->verify_ctx) != ECCONNECT_SIGN_rsa_pss_pkcs8) {
        return ECRYPT_INVALID_PARAMETER;
    }
    if (msg->message_hdr.message_type == ECRYPT_SECURE_MESSAGE_EC_SIGNED
        && ecconnect_verify_get_alg_id(ctx->verify_ctx) != ECCONNECT_SIGN_ecdsa_none_pkcs8) {
        return ECRYPT_INVALID_PARAMETER;
    }
    /*
     * Note that this allows "wrapped_message" to be longer than expected from the header,
     * with some unused bits of data at the end. Historically, this has been allowed and
     * it MUST be kept this way for the sake of compatibility. Normally, in cryptography,
     * you should detect and report this condition, but hysterical raisins do object.
     *
     * The reason here is that some of the high-level wrappers (in Go, Java/Kotlin, C++)
     * have been producing Secure Messages slightly longer than necessary. They have been
     * doing this because of a bug in their implementation, enabled by an idiosyncrasy in
     * Secure Message implementation in Ecrypt Core.
     *
     * When you first call ecrypt_secure_message_sign() with NULL output buffer to measure
     * the expected output length, Ecrypt may return a length which is slightly bigger than
     * the actual output length would be on the second ecrypt_secure_message_sign() call.
     * (This is because OpenSSL API is that way. Deal with it.) The abovementioned wrappers
     * ignored the correct length returned on the second call and returned buffers allocated
     * with the length obtained on the first call--larger by 2 bytes for ECDSA signatures.
     *
     * Hence, do allow extra bytes at the end of the "wrapped_message", more than it must
     * have based on the information encoded in the header. This is necessary for Ecrypt
     * to be able to verify all those overlong Secure Messages produced in the past.
     */
    if (wrapped_message_length < total_signed_message_length(msg)) {
        return ECRYPT_INVALID_PARAMETER;
    }
    if (message == NULL || (*message_length) < msg->message_hdr.message_length) {
        (*message_length) = msg->message_hdr.message_length;
        return ECRYPT_BUFFER_TOO_SMALL;
    }
    ECRYPT_CHECK(ecconnect_verify_update(ctx->verify_ctx,
                                     wrapped_message + sizeof(ecrypt_secure_signed_message_hdr_t),
                                     msg->message_hdr.message_length)
                 == ECRYPT_SUCCESS);
    ECRYPT_CHECK(ecconnect_verify_final(ctx->verify_ctx,
                                    wrapped_message + sizeof(ecrypt_secure_signed_message_hdr_t)
                                        + msg->message_hdr.message_length,
                                    msg->signature_length)
                 == ECRYPT_SUCCESS);
    memcpy(message,
           wrapped_message + sizeof(ecrypt_secure_signed_message_hdr_t),
           msg->message_hdr.message_length);
    (*message_length) = msg->message_hdr.message_length;
    return ECRYPT_SUCCESS;
}

ecrypt_status_t ecrypt_secure_message_verifier_destroy(ecrypt_secure_message_verifier_t* ctx)
{
    ecconnect_verify_destroy(ctx->verify_ctx);
    free(ctx);
    return ECRYPT_SUCCESS;
}

/* secure_encrypted_message*/
typedef struct symm_init_ctx_type {
    uint8_t passwd[ECRYPT_RSA_SYMM_PASSWD_LENGTH];
    uint8_t salt[ECRYPT_RSA_SYMM_SALT_LENGTH];
} symm_init_ctx_t;

struct ecrypt_secure_message_rsa_encrypt_worker_type {
    ecconnect_asym_cipher_t* asym_cipher;
};

typedef struct ecrypt_secure_message_rsa_encrypt_worker_type ecrypt_secure_message_rsa_encrypter_t;
ecrypt_status_t ecrypt_secure_message_rsa_encrypter_destroy(ecrypt_secure_message_rsa_encrypter_t* ctx);

ecrypt_secure_message_rsa_encrypter_t* ecrypt_secure_message_rsa_encrypter_init(
    const uint8_t* peer_public_key, const size_t peer_public_key_length)
{
    ECRYPT_CHECK_PARAM_(peer_public_key != NULL);
    ECRYPT_CHECK_PARAM_(peer_public_key_length != 0);
    ecrypt_secure_message_rsa_encrypter_t* ctx = malloc(sizeof(ecrypt_secure_message_rsa_encrypter_t));
    ECRYPT_CHECK_(ctx != NULL);
    ctx->asym_cipher = ecconnect_asym_cipher_create(peer_public_key,
                                                peer_public_key_length,
                                                ECCONNECT_ASYM_CIPHER_OAEP);
    ECRYPT_IF_FAIL_(ctx->asym_cipher != NULL, ecrypt_secure_message_rsa_encrypter_destroy(ctx));
    return ctx;
}

typedef struct ecrypt_secure_rsa_encrypted_message_hdr_type {
    ecrypt_secure_encrypted_message_hdr_t msg;
    uint32_t encrypted_passwd_length;
} ecrypt_secure_rsa_encrypted_message_hdr_t;

ecrypt_status_t ecrypt_secure_message_rsa_encrypter_proceed(ecrypt_secure_message_rsa_encrypter_t* ctx,
                                                            const uint8_t* message,
                                                            const size_t message_length,
                                                            uint8_t* wrapped_message,
                                                            size_t* wrapped_message_length)
{
    size_t symm_passwd_length = 0;
    size_t seal_message_length = 0;
    ECRYPT_CHECK(ecconnect_asym_cipher_encrypt(ctx->asym_cipher, (const uint8_t*)"123", 3, NULL, &symm_passwd_length)
                 == ECRYPT_BUFFER_TOO_SMALL);
    ECRYPT_CHECK(
        ecrypt_secure_cell_encrypt_seal((const uint8_t*)"123", 3, NULL, 0, message, message_length, NULL, &seal_message_length)
        == ECRYPT_BUFFER_TOO_SMALL);
    if (wrapped_message == NULL
        || (*wrapped_message_length) < (sizeof(ecrypt_secure_rsa_encrypted_message_hdr_t)
                                        + symm_passwd_length + seal_message_length)) {
        (*wrapped_message_length) = (sizeof(ecrypt_secure_rsa_encrypted_message_hdr_t)
                                     + symm_passwd_length + seal_message_length);
        return ECRYPT_BUFFER_TOO_SMALL;
    }
    //  symm_init_ctx_t symm_passwd_salt;
    uint8_t symm_passwd[ECRYPT_RSA_SYMM_PASSWD_LENGTH];
    ECRYPT_CHECK(ecconnect_rand(symm_passwd, sizeof(symm_passwd)) == ECRYPT_SUCCESS);
    uint8_t* encrypted_symm_pass = wrapped_message + sizeof(ecrypt_secure_rsa_encrypted_message_hdr_t);
    size_t encrypted_symm_pass_length = symm_passwd_length;
    ECRYPT_CHECK(ecconnect_asym_cipher_encrypt(ctx->asym_cipher,
                                           symm_passwd,
                                           sizeof(symm_passwd),
                                           encrypted_symm_pass,
                                           &encrypted_symm_pass_length)
                 == ECRYPT_SUCCESS);
    (((ecrypt_secure_rsa_encrypted_message_hdr_t*)wrapped_message)->encrypted_passwd_length) =
        (uint32_t)encrypted_symm_pass_length;
    uint8_t* encrypted_message = encrypted_symm_pass + encrypted_symm_pass_length;
    size_t encrypted_message_length = seal_message_length;
    ECRYPT_CHECK(ecrypt_secure_cell_encrypt_seal(symm_passwd,
                                                 sizeof(symm_passwd),
                                                 NULL,
                                                 0,
                                                 message,
                                                 message_length,
                                                 encrypted_message,
                                                 &encrypted_message_length)
                 == ECRYPT_SUCCESS);
    (*wrapped_message_length) = sizeof(ecrypt_secure_rsa_encrypted_message_hdr_t)
                                + encrypted_symm_pass_length + encrypted_message_length;
    ((ecrypt_secure_encrypted_message_hdr_t*)wrapped_message)->message_hdr.message_type =
        ECRYPT_SECURE_MESSAGE_RSA_ENCRYPTED;
    ((ecrypt_secure_encrypted_message_hdr_t*)wrapped_message)->message_hdr.message_length = (uint32_t)(
        *wrapped_message_length);
    return ECRYPT_SUCCESS;
}

ecrypt_status_t ecrypt_secure_message_rsa_encrypter_destroy(ecrypt_secure_message_rsa_encrypter_t* ctx)
{
    ECRYPT_CHECK_PARAM(ctx != NULL);
    if (ctx->asym_cipher != NULL) {
        ecconnect_asym_cipher_destroy(ctx->asym_cipher);
    }
    free(ctx);
    return ECRYPT_SUCCESS;
}

typedef struct ecrypt_secure_message_rsa_encrypt_worker_type ecrypt_secure_message_rsa_decrypter_t;
ecrypt_status_t ecrypt_secure_message_rsa_decrypter_destroy(ecrypt_secure_message_rsa_decrypter_t* ctx);

ecrypt_secure_message_rsa_decrypter_t* ecrypt_secure_message_rsa_decrypter_init(
    const uint8_t* private_key, const size_t private_key_length)
{
    ECRYPT_CHECK_PARAM_(private_key != NULL);
    ECRYPT_CHECK_PARAM_(private_key_length != 0);
    ecrypt_secure_message_rsa_decrypter_t* ctx = malloc(sizeof(ecrypt_secure_message_rsa_decrypter_t));
    ECRYPT_CHECK_(ctx != NULL);
    ctx->asym_cipher = ecconnect_asym_cipher_create(private_key, private_key_length, ECCONNECT_ASYM_CIPHER_OAEP);
    ECRYPT_IF_FAIL_(ctx->asym_cipher != NULL, ecrypt_secure_message_rsa_encrypter_destroy(ctx));
    return ctx;
}

ecrypt_status_t ecrypt_secure_message_rsa_decrypter_proceed(ecrypt_secure_message_rsa_decrypter_t* ctx,
                                                            const uint8_t* wrapped_message,
                                                            const size_t wrapped_message_length,
                                                            uint8_t* message,
                                                            size_t* message_length)
{
    ECRYPT_CHECK_PARAM(wrapped_message_length > sizeof(ecrypt_secure_rsa_encrypted_message_hdr_t));
    ECRYPT_CHECK_PARAM(((const ecrypt_secure_encrypted_message_hdr_t*)wrapped_message)->message_hdr.message_type
                       == ECRYPT_SECURE_MESSAGE_RSA_ENCRYPTED);
    ECRYPT_CHECK_PARAM(((const ecrypt_secure_encrypted_message_hdr_t*)wrapped_message)->message_hdr.message_length
                       == wrapped_message_length);
    /*
     * Make sure the code below does not trigger an underflow if the header is corrupted.
     * The subtraction subexpression does not underflow because of the check we made before.
     * (And yes, this code needs cleanup. I intentionally leave it ugly.)
     */
    if ((wrapped_message_length - sizeof(ecrypt_secure_rsa_encrypted_message_hdr_t))
        < ((const ecrypt_secure_rsa_encrypted_message_hdr_t*)wrapped_message)->encrypted_passwd_length) {
        return ECRYPT_FAIL;
    }
    size_t ml = 0;
    ECRYPT_CHECK(
        ecrypt_secure_cell_decrypt_seal((const uint8_t*)"123",
                                        3,
                                        NULL,
                                        0,
                                        wrapped_message + sizeof(ecrypt_secure_rsa_encrypted_message_hdr_t)
                                            + ((const ecrypt_secure_rsa_encrypted_message_hdr_t*)wrapped_message)
                                                  ->encrypted_passwd_length,
                                        wrapped_message_length
                                            - sizeof(ecrypt_secure_rsa_encrypted_message_hdr_t)
                                            - ((const ecrypt_secure_rsa_encrypted_message_hdr_t*)wrapped_message)
                                                  ->encrypted_passwd_length,
                                        NULL,
                                        &ml)
        == ECRYPT_BUFFER_TOO_SMALL);
    if ((message == NULL) || ((*message_length) < ml)) {
        (*message_length) = ml;
        return ECRYPT_BUFFER_TOO_SMALL;
    }
    uint8_t sym_ctx_buffer[1024];
    size_t sym_ctx_length_ = sizeof(sym_ctx_buffer);
    const uint8_t* wrapped_message_ = wrapped_message;
    wrapped_message_ += sizeof(ecrypt_secure_rsa_encrypted_message_hdr_t);
    size_t wrapped_message_length_ = wrapped_message_length;
    wrapped_message_length_ -= sizeof(ecrypt_secure_rsa_encrypted_message_hdr_t);
    ECRYPT_CHECK(ecconnect_asym_cipher_decrypt(ctx->asym_cipher,
                                           wrapped_message_,
                                           ((const ecrypt_secure_rsa_encrypted_message_hdr_t*)wrapped_message)
                                               ->encrypted_passwd_length,
                                           sym_ctx_buffer,
                                           &sym_ctx_length_)
                 == ECRYPT_SUCCESS);
    wrapped_message_ += ((const ecrypt_secure_rsa_encrypted_message_hdr_t*)wrapped_message)->encrypted_passwd_length;
    wrapped_message_length_ -=
        ((const ecrypt_secure_rsa_encrypted_message_hdr_t*)wrapped_message)->encrypted_passwd_length;
    ECRYPT_CHECK(ecrypt_secure_cell_decrypt_seal(sym_ctx_buffer,
                                                 sym_ctx_length_,
                                                 NULL,
                                                 0,
                                                 wrapped_message_,
                                                 wrapped_message_length_,
                                                 message,
                                                 message_length)
                 == ECRYPT_SUCCESS);
    return ECRYPT_SUCCESS;
}

ecrypt_status_t ecrypt_secure_message_rsa_decrypter_destroy(ecrypt_secure_message_rsa_decrypter_t* ctx)
{
    return ecrypt_secure_message_rsa_encrypter_destroy(ctx);
}

struct ecrypt_secure_message_ec_worker_type {
    uint8_t shared_secret[128];
    size_t shared_secret_length;
};

typedef struct ecrypt_secure_message_ec_worker_type ecrypt_secure_message_ec_t;

ecrypt_status_t ecrypt_secure_message_ec_encrypter_destroy(ecrypt_secure_message_ec_t* ctx);

ecrypt_secure_message_ec_t* ecrypt_secure_message_ec_encrypter_init(const uint8_t* private_key,
                                                                    const size_t private_key_length,
                                                                    const uint8_t* peer_public_key,
                                                                    const size_t peer_public_key_length)
{
    ECRYPT_CHECK_PARAM_(private_key != NULL);
    ECRYPT_CHECK_PARAM_(private_key_length != 0);
    ECRYPT_CHECK_PARAM_(peer_public_key != NULL);
    ECRYPT_CHECK_PARAM_(peer_public_key_length != 0);
    ecrypt_secure_message_ec_t* ctx = malloc(sizeof(ecrypt_secure_message_ec_t));
    ECRYPT_CHECK_(ctx != NULL);
    ctx->shared_secret_length = sizeof(ctx->shared_secret);
    ecconnect_asym_ka_t* km = ecconnect_asym_ka_create(ECCONNECT_ASYM_KA_EC_P256);
    ECRYPT_CHECK__(km, ecrypt_secure_message_ec_encrypter_destroy(ctx); return NULL);
    ECRYPT_CHECK__(ecconnect_asym_ka_import_key(km, private_key, private_key_length) == ECRYPT_SUCCESS,
                   ecrypt_secure_message_ec_encrypter_destroy(ctx);
                   ecconnect_asym_ka_destroy(km);
                   return NULL);
    ECRYPT_CHECK__(ecconnect_asym_ka_derive(km,
                                        peer_public_key,
                                        peer_public_key_length,
                                        ctx->shared_secret,
                                        &ctx->shared_secret_length)
                       == ECRYPT_SUCCESS,
                   ecrypt_secure_message_ec_encrypter_destroy(ctx);
                   ecconnect_asym_ka_destroy(km);
                   return NULL);
    ecconnect_asym_ka_destroy(km);
    return ctx;
}
ecrypt_status_t ecrypt_secure_message_ec_encrypter_proceed(ecrypt_secure_message_ec_t* ctx,
                                                           const uint8_t* message,
                                                           const size_t message_length,
                                                           uint8_t* wrapped_message,
                                                           size_t* wrapped_message_length)
{
    ECRYPT_CHECK_PARAM(ctx != NULL);
    size_t encrypted_message_length = 0;
    ECRYPT_CHECK(ecrypt_secure_cell_encrypt_seal(ctx->shared_secret,
                                                 ctx->shared_secret_length,
                                                 NULL,
                                                 0,
                                                 message,
                                                 message_length,
                                                 NULL,
                                                 &encrypted_message_length)
                     == ECRYPT_BUFFER_TOO_SMALL
                 && encrypted_message_length != 0);
    if (wrapped_message == NULL
        || (*wrapped_message_length)
               < (sizeof(ecrypt_secure_encrypted_message_hdr_t) + encrypted_message_length)) {
        (*wrapped_message_length) = (sizeof(ecrypt_secure_encrypted_message_hdr_t)
                                     + encrypted_message_length);
        return ECRYPT_BUFFER_TOO_SMALL;
    }
    ecrypt_secure_encrypted_message_hdr_t* hdr = (ecrypt_secure_encrypted_message_hdr_t*)wrapped_message;
    hdr->message_hdr.message_type = ECRYPT_SECURE_MESSAGE_EC_ENCRYPTED;
    hdr->message_hdr.message_length = (uint32_t)(sizeof(ecrypt_secure_encrypted_message_hdr_t)
                                                 + encrypted_message_length);
    encrypted_message_length = (*wrapped_message_length) - sizeof(ecrypt_secure_encrypted_message_hdr_t);
    ECRYPT_CHECK(ecrypt_secure_cell_encrypt_seal(ctx->shared_secret,
                                                 ctx->shared_secret_length,
                                                 NULL,
                                                 0,
                                                 message,
                                                 message_length,
                                                 wrapped_message
                                                     + sizeof(ecrypt_secure_encrypted_message_hdr_t),
                                                 &encrypted_message_length)
                 == ECRYPT_SUCCESS);
    (*wrapped_message_length) = encrypted_message_length + sizeof(ecrypt_secure_encrypted_message_hdr_t);
    return ECRYPT_SUCCESS;
}

ecrypt_status_t ecrypt_secure_message_ec_encrypter_destroy(ecrypt_secure_message_ec_t* ctx)
{
    ECRYPT_CHECK_PARAM(ctx != NULL);
    free(ctx);
    return ECRYPT_SUCCESS;
}

ecrypt_secure_message_ec_t* ecrypt_secure_message_ec_decrypter_init(const uint8_t* private_key,
                                                                    const size_t private_key_length,
                                                                    const uint8_t* peer_public_key,
                                                                    const size_t peer_public_key_length)
{
    return ecrypt_secure_message_ec_encrypter_init(private_key,
                                                   private_key_length,
                                                   peer_public_key,
                                                   peer_public_key_length);
}
ecrypt_status_t ecrypt_secure_message_ec_decrypter_proceed(ecrypt_secure_message_ec_t* ctx,
                                                           const uint8_t* wrapped_message,
                                                           const size_t wrapped_message_length,
                                                           uint8_t* message,
                                                           size_t* message_length)
{
    ECRYPT_CHECK_PARAM(ctx != NULL);
    ECRYPT_CHECK_PARAM(wrapped_message_length > sizeof(ecrypt_secure_encrypted_message_hdr_t));
    ecrypt_secure_encrypted_message_hdr_t* hdr = (ecrypt_secure_encrypted_message_hdr_t*)wrapped_message;
    ECRYPT_CHECK_PARAM(hdr->message_hdr.message_type == ECRYPT_SECURE_MESSAGE_EC_ENCRYPTED
                       && wrapped_message_length == hdr->message_hdr.message_length);
    size_t computed_length = 0;
    ECRYPT_CHECK(ecrypt_secure_cell_decrypt_seal(ctx->shared_secret,
                                                 ctx->shared_secret_length,
                                                 NULL,
                                                 0,
                                                 wrapped_message
                                                     + sizeof(ecrypt_secure_encrypted_message_hdr_t),
                                                 wrapped_message_length
                                                     - sizeof(ecrypt_secure_encrypted_message_hdr_t),
                                                 NULL,
                                                 &computed_length));
    if (message == NULL || (*message_length) < computed_length) {
        (*message_length) = computed_length;
        return ECRYPT_BUFFER_TOO_SMALL;
    }
    ECRYPT_CHECK(ecrypt_secure_cell_decrypt_seal(ctx->shared_secret,
                                                 ctx->shared_secret_length,
                                                 NULL,
                                                 0,
                                                 wrapped_message
                                                     + sizeof(ecrypt_secure_encrypted_message_hdr_t),
                                                 wrapped_message_length
                                                     - sizeof(ecrypt_secure_encrypted_message_hdr_t),
                                                 message,
                                                 message_length)
                 == ECRYPT_SUCCESS);
    return ECRYPT_SUCCESS;
}

ecrypt_status_t ecrypt_secure_message_ec_decrypter_destroy(ecrypt_secure_message_ec_t* ctx)
{
    return ecrypt_secure_message_ec_encrypter_destroy(ctx);
}

struct ecrypt_secure_message_encrypt_worker_type {
    union CTX {
        ecrypt_secure_message_rsa_encrypter_t* rsa_encrypter;
        ecrypt_secure_message_ec_t* ec_encrypter;
    } ctx;
    ecconnect_sign_alg_t alg;
};

ecrypt_secure_message_encrypter_t* ecrypt_secure_message_encrypter_init(const uint8_t* private_key,
                                                                        const size_t private_key_length,
                                                                        const uint8_t* peer_public_key,
                                                                        const size_t peer_public_key_length)
{
    ECRYPT_CHECK_(private_key != NULL && private_key_length != 0);
    ECRYPT_CHECK_(peer_public_key != NULL && peer_public_key_length != 0);
    ecconnect_sign_alg_t alg = get_alg_id(private_key, private_key_length);
    ECRYPT_CHECK_(alg != ECCONNECT_SIGN_undefined
                  && alg == get_alg_id(peer_public_key, peer_public_key_length));
    ecrypt_secure_message_encrypter_t* ctx = malloc(sizeof(ecrypt_secure_message_encrypter_t));
    ECRYPT_CHECK_MALLOC_(ctx);
    switch (alg) {
    case ECCONNECT_SIGN_ecdsa_none_pkcs8:
        ctx->ctx.ec_encrypter = ecrypt_secure_message_ec_encrypter_init(private_key,
                                                                        private_key_length,
                                                                        peer_public_key,
                                                                        peer_public_key_length);
        ECRYPT_IF_FAIL_(ctx->ctx.ec_encrypter, free(ctx));
        ctx->alg = alg;
        return ctx;
    case ECCONNECT_SIGN_rsa_pss_pkcs8:
        ctx->ctx.rsa_encrypter = ecrypt_secure_message_rsa_encrypter_init(peer_public_key,
                                                                          peer_public_key_length);
        ECRYPT_IF_FAIL_(ctx->ctx.rsa_encrypter, free(ctx));
        ctx->alg = alg;
        return ctx;
    default:
        free(ctx);
        return NULL;
    }
}
ecrypt_status_t ecrypt_secure_message_encrypter_proceed(ecrypt_secure_message_encrypter_t* ctx,
                                                        const uint8_t* message,
                                                        const size_t message_length,
                                                        uint8_t* wrapped_message,
                                                        size_t* wrapped_message_length)
{
    ECRYPT_CHECK(ctx != NULL);
    switch (ctx->alg) {
    case ECCONNECT_SIGN_ecdsa_none_pkcs8:
        return ecrypt_secure_message_ec_encrypter_proceed(ctx->ctx.ec_encrypter,
                                                          message,
                                                          message_length,
                                                          wrapped_message,
                                                          wrapped_message_length);
    case ECCONNECT_SIGN_rsa_pss_pkcs8:
        return ecrypt_secure_message_rsa_encrypter_proceed(ctx->ctx.rsa_encrypter,
                                                           message,
                                                           message_length,
                                                           wrapped_message,
                                                           wrapped_message_length);
    default:
        return ECRYPT_FAIL;
    }
    return ECRYPT_FAIL;
}
ecrypt_status_t ecrypt_secure_message_encrypter_destroy(ecrypt_secure_message_encrypter_t* ctx)
{
    ECRYPT_CHECK(ctx != NULL);
    ecrypt_status_t res = ECRYPT_SUCCESS;
    switch (ctx->alg) {
    case ECCONNECT_SIGN_ecdsa_none_pkcs8:
        res = ecrypt_secure_message_ec_encrypter_destroy(ctx->ctx.ec_encrypter);
        break;
    case ECCONNECT_SIGN_rsa_pss_pkcs8:
        res = ecrypt_secure_message_rsa_encrypter_destroy(ctx->ctx.rsa_encrypter);
        break;
    default:
        return ECRYPT_FAIL;
    }
    if (ECRYPT_SUCCESS == res) {
        free(ctx);
    }
    return res;
}

ecrypt_secure_message_decrypter_t* ecrypt_secure_message_decrypter_init(const uint8_t* private_key,
                                                                        const size_t private_key_length,
                                                                        const uint8_t* peer_public_key,
                                                                        const size_t peer_public_key_length)
{
    ECRYPT_CHECK_(private_key != NULL && private_key_length != 0);
    ECRYPT_CHECK_(peer_public_key != NULL && peer_public_key_length != 0);
    ecconnect_sign_alg_t alg = get_alg_id(private_key, private_key_length);
    ECRYPT_CHECK_(alg != ECCONNECT_SIGN_undefined
                  && alg == get_alg_id(peer_public_key, peer_public_key_length));
    ecrypt_secure_message_decrypter_t* ctx = malloc(sizeof(ecrypt_secure_message_decrypter_t));
    ECRYPT_CHECK_MALLOC_(ctx);
    switch (alg) {
    case ECCONNECT_SIGN_ecdsa_none_pkcs8:
        ctx->ctx.ec_encrypter = ecrypt_secure_message_ec_decrypter_init(private_key,
                                                                        private_key_length,
                                                                        peer_public_key,
                                                                        peer_public_key_length);
        ECRYPT_CHECK__(ctx->ctx.ec_encrypter, free(ctx); return NULL);
        ctx->alg = alg;
        return ctx;
    case ECCONNECT_SIGN_rsa_pss_pkcs8:
        ctx->ctx.rsa_encrypter = ecrypt_secure_message_rsa_decrypter_init(private_key,
                                                                          private_key_length);
        ECRYPT_CHECK__(ctx->ctx.rsa_encrypter, free(ctx); return NULL);
        ctx->alg = alg;
        return ctx;
    default:
        free(ctx);
        return NULL;
    }
}

ecrypt_status_t ecrypt_secure_message_decrypter_proceed(ecrypt_secure_message_decrypter_t* ctx,
                                                        const uint8_t* wrapped_message,
                                                        const size_t wrapped_message_length,
                                                        uint8_t* message,
                                                        size_t* message_length)
{
    ECRYPT_CHECK(ctx != NULL);
    switch (ctx->alg) {
    case ECCONNECT_SIGN_ecdsa_none_pkcs8:
        return ecrypt_secure_message_ec_decrypter_proceed(ctx->ctx.ec_encrypter,
                                                          wrapped_message,
                                                          wrapped_message_length,
                                                          message,
                                                          message_length);
    case ECCONNECT_SIGN_rsa_pss_pkcs8:
        return ecrypt_secure_message_rsa_decrypter_proceed(ctx->ctx.rsa_encrypter,
                                                           wrapped_message,
                                                           wrapped_message_length,
                                                           message,
                                                           message_length);
    default:
        return ECRYPT_FAIL;
    }
    return ECRYPT_FAIL;
}

ecrypt_status_t ecrypt_secure_message_decrypter_destroy(ecrypt_secure_message_decrypter_t* ctx)
{
    ECRYPT_CHECK(ctx != NULL);
    ecrypt_status_t res = ECRYPT_SUCCESS;
    switch (ctx->alg) {
    case ECCONNECT_SIGN_ecdsa_none_pkcs8:
        res = ecrypt_secure_message_ec_decrypter_destroy(ctx->ctx.ec_encrypter);
        break;
    case ECCONNECT_SIGN_rsa_pss_pkcs8:
        res = ecrypt_secure_message_rsa_decrypter_destroy(ctx->ctx.rsa_encrypter);
        break;
    default:
        return ECRYPT_FAIL;
    }
    if (ECRYPT_SUCCESS == res) {
        free(ctx);
    }
    return res;
}
