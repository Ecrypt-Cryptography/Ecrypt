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

#include "ecconnect/openssl/ecconnect_rsa_common.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#ifndef ECCONNECT_RSA_KEY_LENGTH
#define ECCONNECT_RSA_KEY_LENGTH 2048
#endif

ecconnect_status_t ecconnect_rsa_gen_key(EVP_PKEY** ppkey)
{
    ecconnect_status_t res = ECCONNECT_FAIL;
    BIGNUM* pub_exp = NULL;
    EVP_PKEY_CTX* pkey_ctx = NULL;

    if (!ppkey) {
        return ECCONNECT_INVALID_PARAMETER;
    }

    pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pkey_ctx) {
        res = ECCONNECT_NO_MEMORY;
        goto err;
    }

    if (EVP_PKEY_keygen_init(pkey_ctx) != 1) {
        res = ECCONNECT_INVALID_PARAMETER;
        goto err;
    }

    /* Although it seems that OpenSSL/LibreSSL use 0x10001 as default public exponent, we will set
     * it explicitly just in case */
    pub_exp = BN_new();
    if (!pub_exp) {
        res = ECCONNECT_NO_MEMORY;
        goto err;
    }

    if (!BN_set_word(pub_exp, RSA_F4)) {
        res = ECCONNECT_FAIL;
        goto err;
    }

    /* Passing ownership over pub_exp to EVP_PKEY_CTX */
    if (1 > EVP_PKEY_CTX_ctrl(pkey_ctx, -1, -1, EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP, 0, pub_exp)) {
        res = ECCONNECT_FAIL;
        goto err;
    }
    pub_exp = NULL;

    /* Override default key size for RSA key. Currently OpenSSL has default key size of 1024.
     * LibreSSL has 2048. We will put 2048 explicitly */
    if (1 > EVP_PKEY_CTX_ctrl(pkey_ctx, -1, -1, EVP_PKEY_CTRL_RSA_KEYGEN_BITS, ECCONNECT_RSA_KEY_LENGTH, NULL)) {
        res = ECCONNECT_FAIL;
        goto err;
    }

    if (EVP_PKEY_keygen(pkey_ctx, ppkey) != 1) {
        res = ECCONNECT_FAIL;
        goto err;
    }

    res = ECCONNECT_SUCCESS;

err:
    BN_free(pub_exp);
    EVP_PKEY_CTX_free(pkey_ctx);

    return res;
}

ecconnect_status_t ecconnect_rsa_import_key(EVP_PKEY* pkey, const void* key, const size_t key_length)
{
    const ecconnect_container_hdr_t* hdr = key;

    if (!pkey) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    if (EVP_PKEY_RSA != EVP_PKEY_id(pkey) || key_length < sizeof(ecconnect_container_hdr_t)) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    switch (hdr->tag[0]) {
    case 'R':
        return ecconnect_rsa_priv_key_to_engine_specific(hdr,
                                                     key_length,
                                                     ((ecconnect_engine_specific_rsa_key_t**)&pkey));
    case 'U':
        return ecconnect_rsa_pub_key_to_engine_specific(hdr,
                                                    key_length,
                                                    ((ecconnect_engine_specific_rsa_key_t**)&pkey));
    }
    return ECCONNECT_INVALID_PARAMETER;
}

ecconnect_status_t ecconnect_rsa_export_key(const EVP_PKEY* pkey, void* key, size_t* key_length, bool isprivate)
{
    if (!pkey) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    if (isprivate) {
        return ecconnect_engine_specific_to_rsa_priv_key((const ecconnect_engine_specific_rsa_key_t*)pkey,
                                                     (ecconnect_container_hdr_t*)key,
                                                     key_length);
    }

    return ecconnect_engine_specific_to_rsa_pub_key((const ecconnect_engine_specific_rsa_key_t*)pkey,
                                                (ecconnect_container_hdr_t*)key,
                                                key_length);
}
