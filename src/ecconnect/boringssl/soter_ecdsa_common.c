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

#include "ecconnect/boringssl/ecconnect_ecdsa_common.h"

#include <openssl/ec.h>
#include <openssl/evp.h>

#include "ecconnect/boringssl/ecconnect_engine.h"
#include "ecconnect/ecconnect_ec_key.h"

ecconnect_status_t ecconnect_ec_gen_key(EVP_PKEY_CTX* pkey_ctx)
{
    EVP_PKEY* pkey;
    EC_KEY* ec = NULL;
    if (!pkey_ctx) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    pkey = EVP_PKEY_CTX_get0_pkey(pkey_ctx);
    if (!pkey) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    if (EVP_PKEY_EC != EVP_PKEY_id(pkey)) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec) {
        return ECCONNECT_ENGINE_FAIL;
    }
    if (EC_KEY_generate_key(ec) != 1) {
        EC_KEY_free(ec);
        return ECCONNECT_ENGINE_FAIL;
    }
    if (EVP_PKEY_assign_EC_KEY(pkey, ec) != 1) {
        EC_KEY_free(ec);
        return ECCONNECT_ENGINE_FAIL;
    }
    return ECCONNECT_SUCCESS;
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
