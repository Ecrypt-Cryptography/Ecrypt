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

#include "ecconnect/ecconnect_sym.h"

#include <string.h>

#include <openssl/cipher.h>
#include <openssl/err.h>

#include "ecconnect/boringssl/ecconnect_engine.h"

#define ECCONNECT_SYM_MAX_KEY_LENGTH 128
#define ECCONNECT_SYM_MAX_IV_LENGTH 16
#define ECCONNECT_AES_GCM_AUTH_TAG_LENGTH 16

ecconnect_status_t ecconnect_pbkdf2(const uint8_t* password,
                            const size_t password_length,
                            const uint8_t* salt,
                            const size_t salt_length,
                            uint8_t* key,
                            const size_t* key_length)
{
    if (!PKCS5_PBKDF2_HMAC((const char*)password,
                           (const int)password_length,
                           salt,
                           (const int)salt_length,
                           0,
                           EVP_sha256(),
                           (const int)(*key_length),
                           key)) {
        return ECCONNECT_FAIL;
    }
    return ECCONNECT_SUCCESS;
}

ecconnect_status_t ecconnect_nokdf(const uint8_t* password,
                           const size_t password_length,
                           uint8_t* key,
                           const size_t* key_length)
{
    if (password_length < (*key_length)) {
        return ECCONNECT_FAIL;
    }
    memcpy(key, password, (*key_length));
    return ECCONNECT_SUCCESS;
}

ecconnect_status_t ecconnect_withkdf(uint32_t alg,
                             const uint8_t* password,
                             const size_t password_length,
                             const uint8_t* salt,
                             const size_t salt_length,
                             uint8_t* key,
                             size_t* key_length)
{
    switch (alg & ECCONNECT_SYM_KDF_MASK) {
    case ECCONNECT_SYM_NOKDF:
        return ecconnect_nokdf(password, password_length, key, key_length);
        break;
    case ECCONNECT_SYM_PBKDF2:
        return ecconnect_pbkdf2(password, password_length, salt, salt_length, key, key_length);
        break;
    }
    return ECCONNECT_INVALID_PARAMETER;
}

const EVP_CIPHER* algid_to_evp(uint32_t alg)
{
    switch (alg & (ECCONNECT_SYM_ALG_MASK | ECCONNECT_SYM_PADDING_MASK | ECCONNECT_SYM_KEY_LENGTH_MASK)) {
    case ECCONNECT_SYM_AES_ECB_PKCS7 | ECCONNECT_SYM_256_KEY_LENGTH:
        return EVP_aes_256_ecb();
    case ECCONNECT_SYM_AES_ECB_PKCS7 | ECCONNECT_SYM_192_KEY_LENGTH:
        return EVP_aes_192_ecb();
    case ECCONNECT_SYM_AES_ECB_PKCS7 | ECCONNECT_SYM_128_KEY_LENGTH:
        return EVP_aes_128_ecb();
    case ECCONNECT_SYM_AES_CTR | ECCONNECT_SYM_256_KEY_LENGTH:
        return EVP_aes_256_ctr();
    case ECCONNECT_SYM_AES_CTR | ECCONNECT_SYM_192_KEY_LENGTH:
        return EVP_aes_192_ctr();
    case ECCONNECT_SYM_AES_CTR | ECCONNECT_SYM_128_KEY_LENGTH:
        return EVP_aes_128_ctr();
/*
 * Workaround for using BoringSSL on iOS, because XTS is not included in BoringSSL pod
 * implementation. see
 * https://github.com/CocoaPods/Specs/blob/master/Specs/0/8/a/BoringSSL/10.0.6/BoringSSL.podspec.json#L44
 * see https://github.com/cossacklabs/ecrypt/issues/223#issuecomment-432720576
 */
#ifndef ECCONNECT_BORINGSSL_DISABLE_XTS
    case ECCONNECT_SYM_AES_XTS | ECCONNECT_SYM_256_KEY_LENGTH:
        return EVP_aes_256_xts();
#endif
    }
    return NULL;
}

const EVP_CIPHER* algid_to_evp_aead(uint32_t alg)
{
    switch (alg & (ECCONNECT_SYM_ALG_MASK | ECCONNECT_SYM_PADDING_MASK | ECCONNECT_SYM_KEY_LENGTH_MASK)) {
    case ECCONNECT_SYM_AES_GCM | ECCONNECT_SYM_256_KEY_LENGTH:
        return EVP_aes_256_gcm();
    case ECCONNECT_SYM_AES_GCM | ECCONNECT_SYM_192_KEY_LENGTH:
        return EVP_aes_192_gcm();
    case ECCONNECT_SYM_AES_GCM | ECCONNECT_SYM_128_KEY_LENGTH:
        return EVP_aes_128_gcm();
    }
    return NULL;
}

ecconnect_sym_ctx_t* ecconnect_sym_ctx_init(const uint32_t alg,
                                    const void* key,
                                    const size_t key_length,
                                    const void* salt,
                                    const size_t salt_length,
                                    const void* iv,
                                    const size_t iv_length,
                                    bool encrypt)
{
    const EVP_CIPHER* evp = algid_to_evp(alg);
    ECCONNECT_CHECK_PARAM_(evp != NULL);
    ECCONNECT_CHECK_PARAM_(key != NULL);
    ECCONNECT_CHECK_PARAM_(key_length != 0);
    if (salt == NULL) {
        ECCONNECT_CHECK_PARAM_(salt_length == 0);
    }
    if (iv != NULL) {
        ECCONNECT_CHECK_PARAM_(iv_length >= (size_t)EVP_CIPHER_iv_length(evp));
    }
    ecconnect_sym_ctx_t* ctx = NULL;
    ctx = malloc(sizeof(ecconnect_sym_ctx_t));
    ECCONNECT_CHECK_MALLOC_(ctx);
    ctx->alg = alg;
    uint8_t key_[ECCONNECT_SYM_MAX_KEY_LENGTH];
    size_t key_length_ = (alg & ECCONNECT_SYM_KEY_LENGTH_MASK) / 8;
    EVP_CIPHER_CTX_init(&(ctx->evp_sym_ctx));
    ECCONNECT_IF_FAIL_(ecconnect_withkdf(alg, key, key_length, salt, salt_length, key_, &key_length_)
                       == ECCONNECT_SUCCESS,
                   ecconnect_sym_encrypt_destroy(ctx));
    if (encrypt) {
        ECCONNECT_IF_FAIL_(EVP_EncryptInit_ex(&(ctx->evp_sym_ctx), evp, NULL, key_, iv),
                       ecconnect_sym_encrypt_destroy(ctx));
    } else {
        ECCONNECT_IF_FAIL_(EVP_DecryptInit_ex(&(ctx->evp_sym_ctx), evp, NULL, key_, iv),
                       ecconnect_sym_encrypt_destroy(ctx));
    }
    return ctx;
}

ecconnect_sym_ctx_t* ecconnect_sym_aead_ctx_init(const uint32_t alg,
                                         const void* key,
                                         const size_t key_length,
                                         const void* salt,
                                         const size_t salt_length,
                                         const void* iv,
                                         const size_t iv_length,
                                         bool encrypt)
{
    const EVP_CIPHER* evp = algid_to_evp_aead(alg);
    ECCONNECT_CHECK_PARAM_(evp != NULL);
    ECCONNECT_CHECK_PARAM_(key != NULL);
    ECCONNECT_CHECK_PARAM_(key_length != 0);
    if (salt == NULL) {
        ECCONNECT_CHECK_PARAM_(salt_length == 0);
    }
    if (iv != NULL) {
        ECCONNECT_CHECK_PARAM_(iv_length >= (size_t)EVP_CIPHER_iv_length(evp));
    }
    ecconnect_sym_ctx_t* ctx = NULL;
    ctx = malloc(sizeof(ecconnect_sym_ctx_t));
    ECCONNECT_CHECK_MALLOC_(ctx);
    ctx->alg = alg;
    uint8_t key_[ECCONNECT_SYM_MAX_KEY_LENGTH];
    size_t key_length_ = (alg & ECCONNECT_SYM_KEY_LENGTH_MASK) / 8;
    EVP_CIPHER_CTX_init(&(ctx->evp_sym_ctx));
    ECCONNECT_IF_FAIL_(ecconnect_withkdf(alg, key, key_length, salt, salt_length, key_, &key_length_)
                       == ECCONNECT_SUCCESS,
                   ecconnect_sym_encrypt_destroy(ctx));
    if (encrypt) {
        ECCONNECT_IF_FAIL_(EVP_EncryptInit_ex(&(ctx->evp_sym_ctx), evp, NULL, key_, iv),
                       ecconnect_sym_encrypt_destroy(ctx));
    } else {
        ECCONNECT_IF_FAIL_(EVP_DecryptInit_ex(&(ctx->evp_sym_ctx), evp, NULL, key_, iv),
                       ecconnect_sym_encrypt_destroy(ctx));
    }
    return ctx;
}

ecconnect_status_t ecconnect_sym_ctx_update(ecconnect_sym_ctx_t* ctx,
                                    const void* in_data,
                                    const size_t in_data_length,
                                    void* out_data,
                                    size_t* out_data_length,
                                    bool encrypt)
{
    if (encrypt) {
        ECCONNECT_CHECK(EVP_EncryptUpdate(&(ctx->evp_sym_ctx),
                                      out_data,
                                      (int*)out_data_length,
                                      (void*)in_data,
                                      (int)in_data_length)
                    == 1);
    } else {
        ECCONNECT_CHECK(EVP_DecryptUpdate(&(ctx->evp_sym_ctx),
                                      out_data,
                                      (int*)out_data_length,
                                      (void*)in_data,
                                      (int)in_data_length)
                    == 1);
    }
    return ECCONNECT_SUCCESS;
}

ecconnect_status_t ecconnect_sym_ctx_final(ecconnect_sym_ctx_t* ctx, void* out_data, size_t* out_data_length, bool encrypt)
{
    if ((ctx->alg & ECCONNECT_SYM_PADDING_MASK) != 0) {
        if ((*out_data_length) < EVP_CIPHER_CTX_block_size(&(ctx->evp_sym_ctx))) {
            (*out_data_length) = EVP_CIPHER_CTX_block_size(&(ctx->evp_sym_ctx));
            return ECCONNECT_BUFFER_TOO_SMALL;
        }
    }
    if (encrypt) {
        ECCONNECT_CHECK(EVP_EncryptFinal_ex(&(ctx->evp_sym_ctx), out_data, (int*)out_data_length) != 0);
    } else {
        ECCONNECT_CHECK(EVP_DecryptFinal_ex(&(ctx->evp_sym_ctx), out_data, (int*)out_data_length) != 0);
    }
    return ECCONNECT_SUCCESS;
}

ecconnect_status_t ecconnect_sym_aead_ctx_final(ecconnect_sym_ctx_t* ctx, bool encrypt)
{
    uint8_t out_data[16];
    size_t out_data_length = 0;
    if (encrypt) {
        ECCONNECT_CHECK(EVP_EncryptFinal_ex(&(ctx->evp_sym_ctx), out_data, (int*)&out_data_length) != 0
                    && out_data_length == 0);
    } else {
        ECCONNECT_CHECK(EVP_DecryptFinal_ex(&(ctx->evp_sym_ctx), out_data, (int*)&out_data_length) != 0
                    && out_data_length == 0);
    }
    return ECCONNECT_SUCCESS;
}

ecconnect_status_t ecconnect_sym_ctx_destroy(ecconnect_sym_ctx_t* ctx)
{
    EVP_CIPHER_CTX_cleanup(&(ctx->evp_sym_ctx));
    free(ctx);
    return ECCONNECT_SUCCESS;
}

ecconnect_sym_ctx_t* ecconnect_sym_encrypt_create(const uint32_t alg,
                                          const void* key,
                                          const size_t key_length,
                                          const void* salt,
                                          const size_t salt_length,
                                          const void* iv,
                                          const size_t iv_length)
{
    return ecconnect_sym_ctx_init(alg, key, key_length, salt, salt_length, iv, iv_length, true);
}

ecconnect_status_t ecconnect_sym_encrypt_update(ecconnect_sym_ctx_t* ctx,
                                        const void* plain_data,
                                        const size_t plain_data_length,
                                        void* cipher_data,
                                        size_t* cipher_data_length)
{
    if (cipher_data == NULL
        || (*cipher_data_length)
               < (plain_data_length + EVP_CIPHER_CTX_block_size(&(ctx->evp_sym_ctx)) - 1)) {
        (*cipher_data_length) = plain_data_length + EVP_CIPHER_CTX_block_size(&(ctx->evp_sym_ctx)) - 1;
        return ECCONNECT_BUFFER_TOO_SMALL;
    }
    return ecconnect_sym_ctx_update(ctx, plain_data, plain_data_length, cipher_data, cipher_data_length, true);
}

ecconnect_status_t ecconnect_sym_encrypt_final(ecconnect_sym_ctx_t* ctx, void* cipher_data, size_t* cipher_data_length)
{
    return ecconnect_sym_ctx_final(ctx, cipher_data, cipher_data_length, true);
}

ecconnect_status_t ecconnect_sym_encrypt_destroy(ecconnect_sym_ctx_t* ctx)
{
    return ecconnect_sym_ctx_destroy(ctx);
}

ecconnect_sym_ctx_t* ecconnect_sym_decrypt_create(const uint32_t alg,
                                          const void* key,
                                          const size_t key_length,
                                          const void* salt,
                                          const size_t salt_length,
                                          const void* iv,
                                          const size_t iv_length)
{
    return ecconnect_sym_ctx_init(alg, key, key_length, salt, salt_length, iv, iv_length, false);
}

ecconnect_status_t ecconnect_sym_decrypt_update(ecconnect_sym_ctx_t* ctx,
                                        const void* cipher_data,
                                        const size_t cipher_data_length,
                                        void* plain_data,
                                        size_t* plain_data_length)
{
    if (plain_data == NULL
        || (*plain_data_length)
               < (cipher_data_length + EVP_CIPHER_CTX_block_size(&(ctx->evp_sym_ctx)) - 1)) {
        (*plain_data_length) = cipher_data_length + EVP_CIPHER_CTX_block_size(&(ctx->evp_sym_ctx)) - 1;
        return ECCONNECT_BUFFER_TOO_SMALL;
    }
    return ecconnect_sym_ctx_update(ctx, cipher_data, cipher_data_length, plain_data, plain_data_length, false);
}

ecconnect_status_t ecconnect_sym_decrypt_final(ecconnect_sym_ctx_t* ctx, void* plain_data, size_t* plain_data_length)
{
    return ecconnect_sym_ctx_final(ctx, plain_data, plain_data_length, false);
}

ecconnect_status_t ecconnect_sym_decrypt_destroy(ecconnect_sym_ctx_t* ctx)
{
    return ecconnect_sym_ctx_destroy(ctx);
}

ecconnect_sym_ctx_t* ecconnect_sym_aead_encrypt_create(const uint32_t alg,
                                               const void* key,
                                               const size_t key_length,
                                               const void* salt,
                                               const size_t salt_length,
                                               const void* iv,
                                               const size_t iv_length)
{
    return ecconnect_sym_aead_ctx_init(alg, key, key_length, salt, salt_length, iv, iv_length, true);
}

ecconnect_status_t ecconnect_sym_aead_encrypt_update(ecconnect_sym_ctx_t* ctx,
                                             const void* plain_data,
                                             const size_t plain_data_length,
                                             void* cipher_data,
                                             size_t* cipher_data_length)
{
    if (cipher_data == NULL
        || (*cipher_data_length)
               < (plain_data_length + EVP_CIPHER_CTX_block_size(&(ctx->evp_sym_ctx)) - 1)) {
        (*cipher_data_length) = plain_data_length + EVP_CIPHER_CTX_block_size(&(ctx->evp_sym_ctx)) - 1;
        return ECCONNECT_BUFFER_TOO_SMALL;
    }
    (*cipher_data_length) = plain_data_length + EVP_CIPHER_CTX_block_size(&(ctx->evp_sym_ctx)) - 1;
    return ecconnect_sym_ctx_update(ctx, plain_data, plain_data_length, cipher_data, cipher_data_length, true);
}

ecconnect_status_t ecconnect_sym_aead_encrypt_aad(ecconnect_sym_ctx_t* ctx,
                                          const void* plain_data,
                                          const size_t plain_data_length)
{
    size_t tmp = 0;
    return ecconnect_sym_ctx_update(ctx, plain_data, plain_data_length, NULL, &tmp, true);
}

ecconnect_status_t ecconnect_sym_aead_encrypt_final(ecconnect_sym_ctx_t* ctx, void* auth_tag, size_t* auth_tag_length)
{
    if (!auth_tag_length) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    if (!auth_tag || (*auth_tag_length) < ECCONNECT_AES_GCM_AUTH_TAG_LENGTH) {
        (*auth_tag_length) = ECCONNECT_AES_GCM_AUTH_TAG_LENGTH;
        return ECCONNECT_BUFFER_TOO_SMALL;
    }
    ECCONNECT_CHECK(ecconnect_sym_aead_ctx_final(ctx, true) == ECCONNECT_SUCCESS);
    ECCONNECT_CHECK(EVP_CIPHER_CTX_ctrl(&(ctx->evp_sym_ctx),
                                    EVP_CTRL_GCM_GET_TAG,
                                    ECCONNECT_AES_GCM_AUTH_TAG_LENGTH,
                                    auth_tag));
    (*auth_tag_length) = ECCONNECT_AES_GCM_AUTH_TAG_LENGTH;
    return ECCONNECT_SUCCESS;
}

ecconnect_status_t ecconnect_sym_aead_encrypt_destroy(ecconnect_sym_ctx_t* ctx)
{
    return ecconnect_sym_ctx_destroy(ctx);
}

ecconnect_sym_ctx_t* ecconnect_sym_aead_decrypt_create(const uint32_t alg,
                                               const void* key,
                                               const size_t key_length,
                                               const void* salt,
                                               const size_t salt_length,
                                               const void* iv,
                                               const size_t iv_length)
{
    return ecconnect_sym_aead_ctx_init(alg, key, key_length, salt, salt_length, iv, iv_length, false);
}

ecconnect_status_t ecconnect_sym_aead_decrypt_update(ecconnect_sym_ctx_t* ctx,
                                             const void* cipher_data,
                                             const size_t cipher_data_length,
                                             void* plain_data,
                                             size_t* plain_data_length)
{
    if (plain_data == NULL
        || (*plain_data_length)
               < (cipher_data_length + EVP_CIPHER_CTX_block_size(&(ctx->evp_sym_ctx)) - 1)) {
        (*plain_data_length) = cipher_data_length + EVP_CIPHER_CTX_block_size(&(ctx->evp_sym_ctx)) - 1;
        return ECCONNECT_BUFFER_TOO_SMALL;
    }
    return ecconnect_sym_ctx_update(ctx, cipher_data, cipher_data_length, plain_data, plain_data_length, false);
}

ecconnect_status_t ecconnect_sym_aead_decrypt_aad(ecconnect_sym_ctx_t* ctx,
                                          const void* plain_data,
                                          const size_t plain_data_length)
{
    size_t tmp = 0;
    return ecconnect_sym_ctx_update(ctx, plain_data, plain_data_length, NULL, &tmp, false);
}

ecconnect_status_t ecconnect_sym_aead_decrypt_final(ecconnect_sym_ctx_t* ctx,
                                            const void* auth_tag,
                                            const size_t auth_tag_length)
{
    ECCONNECT_CHECK_PARAM(auth_tag != NULL);
    ECCONNECT_CHECK_PARAM(auth_tag_length >= ECCONNECT_AES_GCM_AUTH_TAG_LENGTH);
    ECCONNECT_CHECK(ctx != NULL);
    ECCONNECT_IF_FAIL(EVP_CIPHER_CTX_ctrl(&(ctx->evp_sym_ctx),
                                      EVP_CTRL_GCM_SET_TAG,
                                      ECCONNECT_AES_GCM_AUTH_TAG_LENGTH,
                                      (void*)auth_tag),
                  ecconnect_sym_aead_decrypt_destroy(ctx));
    return ecconnect_sym_aead_ctx_final(ctx, false);
}
ecconnect_status_t ecconnect_sym_aead_decrypt_destroy(ecconnect_sym_ctx_t* ctx)
{
    return ecconnect_sym_ctx_destroy(ctx);
}
