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

#include "ecconnect/openssl/ecconnect_ecdsa_common.h"

#include <openssl/ec.h>
#include <openssl/evp.h>

#include "ecconnect/openssl/ecconnect_engine.h"
#include "ecconnect/ecconnect_ec_key.h"

ecconnect_status_t ecconnect_ec_gen_key(EVP_PKEY** ppkey)
{
    ecconnect_status_t res = ECCONNECT_FAIL;
    EVP_PKEY* param = NULL;
    EVP_PKEY_CTX* param_ctx = NULL;
    EVP_PKEY_CTX* pkey_ctx = NULL;

    if (!ppkey) {
        return ECCONNECT_INVALID_PARAMETER;
    }

    param_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!param_ctx) {
        res = ECCONNECT_NO_MEMORY;
        goto err;
    }

    if (EVP_PKEY_paramgen_init(param_ctx) != 1) {
        res = ECCONNECT_FAIL;
        goto err;
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(param_ctx, NID_X9_62_prime256v1) != 1) {
        res = ECCONNECT_FAIL;
        goto err;
    }
    if (EVP_PKEY_paramgen(param_ctx, &param) != 1) {
        res = ECCONNECT_FAIL;
        goto err;
    }

    pkey_ctx = EVP_PKEY_CTX_new(param, NULL);
    if (!pkey_ctx) {
        res = ECCONNECT_NO_MEMORY;
        goto err;
    }

    if (EVP_PKEY_keygen_init(pkey_ctx) != 1) {
        res = ECCONNECT_FAIL;
        goto err;
    }
    if (EVP_PKEY_keygen(pkey_ctx, ppkey) != 1) {
        res = ECCONNECT_FAIL;
        goto err;
    }

    res = ECCONNECT_SUCCESS;

err:
    EVP_PKEY_CTX_free(param_ctx);
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_PKEY_free(param);

    return res;
}

ecconnect_status_t ecconnect_ec_import_key(EVP_PKEY* pkey, const void* key, const size_t key_length)
{
    const ecconnect_container_hdr_t* hdr = key;
    if (!pkey || !key) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    if (key_length < sizeof(ecconnect_container_hdr_t)) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    if (EVP_PKEY_EC != EVP_PKEY_id(pkey)) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    switch (hdr->tag[0]) {
    case 'R':
        return ecconnect_ec_priv_key_to_engine_specific(hdr,
                                                    key_length,
                                                    ((ecconnect_engine_specific_ec_key_t**)&pkey));
    case 'U':
        return ecconnect_ec_pub_key_to_engine_specific(hdr,
                                                   key_length,
                                                   ((ecconnect_engine_specific_ec_key_t**)&pkey));
    }
    return ECCONNECT_INVALID_PARAMETER;
}

ecconnect_status_t ecconnect_ec_export_private_key(const EVP_PKEY* pkey, void* key, size_t* key_length)
{
    if (!pkey) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    return ecconnect_engine_specific_to_ec_priv_key((const ecconnect_engine_specific_ec_key_t*)pkey,
                                                (ecconnect_container_hdr_t*)key,
                                                key_length);
}

ecconnect_status_t ecconnect_ec_export_public_key(const EVP_PKEY* pkey, bool compressed, void* key, size_t* key_length)
{
    if (!pkey) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    return ecconnect_engine_specific_to_ec_pub_key((const ecconnect_engine_specific_ec_key_t*)pkey,
                                               compressed,
                                               (ecconnect_container_hdr_t*)key,
                                               key_length);
}
