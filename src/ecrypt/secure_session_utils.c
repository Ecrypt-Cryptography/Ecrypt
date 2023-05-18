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

#include "ecrypt/secure_session_utils.h"

#include "ecconnect/ecconnect_ec_key.h"
#include "ecconnect/ecconnect_rsa_key.h"
#include "ecconnect/ecconnect_t.h"

#include "ecrypt/secure_session.h"
#include "ecrypt/secure_session_t.h"
#include "ecrypt/ecrypt_portable_endian.h"

#define MAX_HMAC_SIZE 64 /* For HMAC-SHA512 */

ecconnect_sign_alg_t get_key_sign_type(const void* sign_key, size_t sign_key_length)
{
    const ecconnect_container_hdr_t* key = sign_key;

    if (sign_key_length >= sizeof(ecconnect_container_hdr_t)) {
        if (sign_key_length < be32toh(key->size)) {
            return (ecconnect_sign_alg_t)0xffffffff;
        }

        if (!memcmp(key->tag, EC_PRIV_KEY_PREF, strlen(EC_PRIV_KEY_PREF))) {
            return ECCONNECT_SIGN_ecdsa_none_pkcs8;
        }

        if (!memcmp(key->tag, RSA_PRIV_KEY_PREF, strlen(RSA_PRIV_KEY_PREF))) {
            return ECCONNECT_SIGN_rsa_pss_pkcs8;
        }
    }

    return (ecconnect_sign_alg_t)0xffffffff;
}

ecconnect_sign_alg_t get_peer_key_sign_type(const void* sign_key, size_t sign_key_length)
{
    const ecconnect_container_hdr_t* key = sign_key;

    if (sign_key_length >= sizeof(ecconnect_container_hdr_t)) {
        if (sign_key_length < be32toh(key->size)) {
            return (ecconnect_sign_alg_t)0xffffffff;
        }

        if (!memcmp(key->tag, EC_PUB_KEY_PREF, strlen(EC_PUB_KEY_PREF))) {
            return ECCONNECT_SIGN_ecdsa_none_pkcs8;
        }

        if (!memcmp(key->tag, RSA_PUB_KEY_PREF, strlen(RSA_PUB_KEY_PREF))) {
            return ECCONNECT_SIGN_rsa_pss_pkcs8;
        }
    }

    return (ecconnect_sign_alg_t)0xffffffff;
}

ecrypt_status_t compute_signature(const void* sign_key,
                                  size_t sign_key_length,
                                  const ecconnect_kdf_context_buf_t* sign_data,
                                  size_t sign_data_count,
                                  void* signature,
                                  size_t* signature_length)
{
    ecconnect_sign_ctx_t* sign_ctx = NULL;
    ecconnect_status_t ecconnect_status;
    size_t i;

    sign_ctx = ecconnect_sign_create(get_key_sign_type(sign_key, sign_key_length),
                                 sign_key,
                                 sign_key_length,
                                 NULL,
                                 0);
    if (!sign_ctx) {
        return ECRYPT_FAIL;
    }

    /* This is to compute real signature, not just get output data size */
    if (sign_data && signature) {
        for (i = 0; i < sign_data_count; i++) {
            ecconnect_status = ecconnect_sign_update(sign_ctx, sign_data[i].data, sign_data[i].length);
            if (ECRYPT_SUCCESS != ecconnect_status) {
                goto err;
            }
        }
    }

    ecconnect_status = ecconnect_sign_final(sign_ctx, signature, signature_length);

err:

    ecconnect_sign_destroy(sign_ctx);
    return ecconnect_status;
}

ecrypt_status_t verify_signature(const void* verify_key,
                                 size_t verify_key_length,
                                 const ecconnect_kdf_context_buf_t* sign_data,
                                 size_t sign_data_count,
                                 const void* signature,
                                 size_t signature_length)
{
    ecconnect_sign_ctx_t* sign_ctx = NULL;
    ecconnect_status_t ecconnect_status;
    size_t i;

    sign_ctx = ecconnect_verify_create(get_peer_key_sign_type(verify_key, verify_key_length),
                                   NULL,
                                   0,
                                   verify_key,
                                   verify_key_length);
    if (!sign_ctx) {
        return ECCONNECT_FAIL;
    }

    for (i = 0; i < sign_data_count; i++) {
        ecconnect_status = ecconnect_verify_update(sign_ctx, sign_data[i].data, sign_data[i].length);
        if (ECRYPT_SUCCESS != ecconnect_status) {
            goto err;
        }
    }

    /* TODO: fix verify functions prototypes */
    ecconnect_status = ecconnect_verify_final(sign_ctx, (void*)signature, signature_length);

err:

    /* TODO: cleanup sign ctx */

    ecconnect_sign_destroy(sign_ctx);
    return ecconnect_status;
}

ecrypt_status_t compute_mac(const void* key,
                            size_t key_length,
                            const ecconnect_kdf_context_buf_t* data,
                            size_t data_count,
                            void* mac,
                            size_t* mac_length)
{
    ecconnect_hmac_ctx_t* mac_ctx = ecconnect_hmac_create(ECCONNECT_HASH_SHA256, key, key_length);
    if (!mac_ctx) {
        return ECRYPT_FAIL;
    }
    ecconnect_status_t ecconnect_status;
    size_t i;

    /* This is to compute real mac, not just get output data size */
    if (data && mac) {
        for (i = 0; i < data_count; i++) {
            ecconnect_status = ecconnect_hmac_update(mac_ctx, data[i].data, data[i].length);
            if (ECRYPT_SUCCESS != ecconnect_status) {
                goto err;
            }
        }
    }

    ecconnect_status = ecconnect_hmac_final(mac_ctx, mac, mac_length);

err:

    ecconnect_hmac_destroy(mac_ctx);

    return ecconnect_status;
}

ecrypt_status_t verify_mac(const void* key,
                           size_t key_length,
                           const ecconnect_kdf_context_buf_t* data,
                           size_t data_count,
                           const void* mac,
                           size_t mac_length)
{
    uint8_t computed_mac[MAX_HMAC_SIZE];
    size_t computed_mac_length = sizeof(computed_mac);

    ecrypt_status_t res = compute_mac(key, key_length, data, data_count, computed_mac, &computed_mac_length);
    if (ECRYPT_SUCCESS != res) {
        return res;
    }

    if (mac_length > computed_mac_length) {
        return ECRYPT_INVALID_PARAMETER;
    }

    if (memcmp(mac, computed_mac, mac_length) != 0) {
        return ECRYPT_INVALID_SIGNATURE;
    }

    return ECRYPT_SUCCESS;
}

ecrypt_status_t encrypt_gcm(const void* key,
                            size_t key_length,
                            const void* iv,
                            size_t iv_length,
                            const void* in,
                            size_t in_length,
                            void* out,
                            size_t out_length)
{
    ecconnect_sym_ctx_t* ctx;
    ecconnect_status_t res;

    size_t bytes_encrypted = out_length;

    if (out_length < (in_length + CIPHER_AUTH_TAG_SIZE)) {
        return ECRYPT_BUFFER_TOO_SMALL;
    }

    ctx = ecconnect_sym_aead_encrypt_create(ECCONNECT_SYM_AES_GCM | ECCONNECT_SYM_256_KEY_LENGTH,
                                        key,
                                        key_length,
                                        NULL,
                                        0,
                                        iv,
                                        iv_length);
    if (NULL == ctx) {
        return ECRYPT_FAIL;
    }

    res = ecconnect_sym_aead_encrypt_update(ctx, in, in_length, out, &bytes_encrypted);
    if (ECRYPT_SUCCESS != res) {
        goto err;
    }

    if (in_length != bytes_encrypted) {
        res = ECRYPT_FAIL;
        goto err;
    }

    bytes_encrypted = out_length - bytes_encrypted;
    out_length = bytes_encrypted;

    res = ecconnect_sym_aead_encrypt_final(ctx, ((uint8_t*)out) + in_length, &out_length);
    if (ECRYPT_SUCCESS != res) {
        goto err;
    }

    if (CIPHER_AUTH_TAG_SIZE != out_length) {
        res = ECRYPT_FAIL;
        goto err;
    }

err:

    if (NULL != ctx) {
        ecconnect_sym_encrypt_destroy(ctx);
    }

    return res;

    /* TODO: we will simulate encryption until we fix gcm */
    /*const uint8_t *input = in;
    uint8_t *output = out;

    size_t i;

    if (out_length < (in_length + CIPHER_AUTH_TAG_SIZE))
    {
            return ECRYPT_BUFFER_TOO_SMALL;
    }

    for (i = 0; i < in_length; i++)
    {
            output[i] = input[i] ^ 0xff;
    }

    for (i = in_length; i < (in_length + CIPHER_AUTH_TAG_SIZE); i++)
    {
            output[i] = 0xff;
    }

    return ECRYPT_SUCCESS;*/
}

/*ecrypt_status_t decrypt_gcm(const void *key, size_t key_length, const void *iv, size_t iv_length,
const void *in, size_t in_length, void *out, size_t out_length)
{
        const uint8_t *input = in;
        uint8_t *output = out;

        size_t i;

        if (out_length < (in_length - CIPHER_AUTH_TAG_SIZE))
        {
                return ECRYPT_BUFFER_TOO_SMALL;
        }

        for (i = 0; i < (in_length - CIPHER_AUTH_TAG_SIZE); i++)
        {
                output[i] = input[i] ^ 0xff;
        }

        for (i = (in_length - CIPHER_AUTH_TAG_SIZE); i < in_length; i++)
        {
                if (0xff != input[i])
                {
                        return ECRYPT_INVALID_SIGNATURE;
                }
        }

        return ECRYPT_SUCCESS;
}*/

ecrypt_status_t secure_session_derive_message_keys(secure_session_t* session_ctx)
{
    const char* out_key_label;
    const char* in_key_label;

    const char* out_seq_label;
    const char* in_seq_label;

    ecrypt_status_t res;

    ecconnect_kdf_context_buf_t context = {(const uint8_t*)&(session_ctx->session_id),
                                       sizeof(session_ctx->session_id)};

    if (session_ctx->is_client) {
        out_key_label = "Ecrypt secure session client key";
        in_key_label = "Ecrypt secure session server key";

        out_seq_label = "Ecrypt secure session client initial sequence number";
        in_seq_label = "Ecrypt secure session server initial sequence number";
    } else {
        out_key_label = "Ecrypt secure session server key";
        in_key_label = "Ecrypt secure session client key";

        out_seq_label = "Ecrypt secure session server initial sequence number";
        in_seq_label = "Ecrypt secure session client initial sequence number";
    }

    res = ecconnect_kdf(session_ctx->session_master_key,
                    SESSION_MASTER_KEY_LENGTH,
                    out_key_label,
                    &context,
                    1,
                    session_ctx->out_cipher_key,
                    SESSION_MESSAGE_KEY_LENGTH);
    if (ECRYPT_SUCCESS != res) {
        return res;
    }

    res = ecconnect_kdf(session_ctx->session_master_key,
                    SESSION_MASTER_KEY_LENGTH,
                    in_key_label,
                    &context,
                    1,
                    session_ctx->in_cipher_key,
                    SESSION_MESSAGE_KEY_LENGTH);
    if (ECRYPT_SUCCESS != res) {
        return res;
    }

    res = ecconnect_kdf(session_ctx->session_master_key,
                    SESSION_MASTER_KEY_LENGTH,
                    out_seq_label,
                    &context,
                    1,
                    &(session_ctx->out_seq),
                    sizeof(session_ctx->out_seq));
    if (ECRYPT_SUCCESS != res) {
        return res;
    }

    res = ecconnect_kdf(session_ctx->session_master_key,
                    SESSION_MASTER_KEY_LENGTH,
                    in_seq_label,
                    &context,
                    1,
                    &(session_ctx->in_seq),
                    sizeof(session_ctx->in_seq));
    if (ECRYPT_SUCCESS != res) {
        return res;
    }

    return res;
}
