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

#include "ecconnect/ecconnect_asym_ka.h"

#include <openssl/ec.h>

#include "ecconnect/openssl/ecconnect_engine.h"
#include "ecconnect/ecconnect_api.h"
#include "ecconnect/ecconnect_ec_key.h"

static int ecconnect_alg_to_curve_nid(ecconnect_asym_ka_alg_t alg)
{
    switch (alg) {
    case ECCONNECT_ASYM_KA_EC_P256:
        return NID_X9_62_prime256v1;
    default:
        return 0;
    }
}

ECCONNECT_PRIVATE_API
ecconnect_status_t ecconnect_asym_ka_init(ecconnect_asym_ka_t* asym_ka_ctx, ecconnect_asym_ka_alg_t alg)
{
    ecconnect_status_t res = ECCONNECT_FAIL;
    EVP_PKEY_CTX* param_ctx = NULL;
    int nid = ecconnect_alg_to_curve_nid(alg);

    if ((!asym_ka_ctx) || (0 == nid)) {
        return ECCONNECT_INVALID_PARAMETER;
    }

    param_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!param_ctx) {
        res = ECCONNECT_NO_MEMORY;
        goto err;
    }

    if (1 != EVP_PKEY_paramgen_init(param_ctx)) {
        res = ECCONNECT_FAIL;
        goto err;
    }
    if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(param_ctx, nid)) {
        res = ECCONNECT_FAIL;
        goto err;
    }
    if (1 != EVP_PKEY_paramgen(param_ctx, &asym_ka_ctx->param)) {
        res = ECCONNECT_FAIL;
        goto err;
    }

    res = ECCONNECT_SUCCESS;

err:
    EVP_PKEY_CTX_free(param_ctx);

    return res;
}

ECCONNECT_PRIVATE_API
ecconnect_status_t ecconnect_asym_ka_cleanup(ecconnect_asym_ka_t* asym_ka_ctx)
{
    if (!asym_ka_ctx) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    if (asym_ka_ctx->param) {
        EVP_PKEY_free(asym_ka_ctx->param);
        asym_ka_ctx->param = NULL;
    }
    if (asym_ka_ctx->pkey) {
        EVP_PKEY_free(asym_ka_ctx->pkey);
        asym_ka_ctx->pkey = NULL;
    }
    return ECCONNECT_SUCCESS;
}

ecconnect_asym_ka_t* ecconnect_asym_ka_create(ecconnect_asym_ka_alg_t alg)
{
    ecconnect_status_t status;
    ecconnect_asym_ka_t* ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        return NULL;
    }

    status = ecconnect_asym_ka_init(ctx, alg);
    if (ECCONNECT_SUCCESS == status) {
        return ctx;
    }

    free(ctx);
    return NULL;
}

ecconnect_status_t ecconnect_asym_ka_destroy(ecconnect_asym_ka_t* asym_ka_ctx)
{
    ecconnect_status_t status;

    if (!asym_ka_ctx) {
        return ECCONNECT_INVALID_PARAMETER;
    }

    status = ecconnect_asym_ka_cleanup(asym_ka_ctx);
    if (ECCONNECT_SUCCESS == status) {
        free(asym_ka_ctx);
        return ECCONNECT_SUCCESS;
    }

    return status;
}

ecconnect_status_t ecconnect_asym_ka_gen_key(ecconnect_asym_ka_t* asym_ka_ctx)
{
    ecconnect_status_t res = ECCONNECT_FAIL;
    EVP_PKEY_CTX* pkey_ctx = NULL;

    if (!asym_ka_ctx || !asym_ka_ctx->param) {
        return ECCONNECT_INVALID_PARAMETER;
    }

    pkey_ctx = EVP_PKEY_CTX_new(asym_ka_ctx->param, NULL);
    if (!pkey_ctx) {
        return ECCONNECT_NO_MEMORY;
    }

    if (EVP_PKEY_keygen_init(pkey_ctx) != 1) {
        res = ECCONNECT_FAIL;
        goto err;
    }

    if (EVP_PKEY_keygen(pkey_ctx, &asym_ka_ctx->pkey) != 1) {
        res = ECCONNECT_FAIL;
        goto err;
    }

    res = ECCONNECT_SUCCESS;

err:
    EVP_PKEY_CTX_free(pkey_ctx);

    return res;
}

ecconnect_status_t ecconnect_asym_ka_import_key(ecconnect_asym_ka_t* asym_ka_ctx, const void* key, size_t key_length)
{
    const ecconnect_container_hdr_t* hdr = key;

    if ((!asym_ka_ctx) || (!key)) {
        return ECCONNECT_INVALID_PARAMETER;
    }

    if (key_length < sizeof(ecconnect_container_hdr_t)) {
        return ECCONNECT_INVALID_PARAMETER;
    }

    /*
     * ecconnect_ec_{priv,pub}_key_to_engine_specific() expect EVP_PKEY of EVP_PKEY_EC type
     * to be already allocated and non-NULL. We might be importing it anew, or we might be
     * replacing previously generated key pair.
     */
    if (asym_ka_ctx->pkey) {
        if (EVP_PKEY_base_id(asym_ka_ctx->pkey) != EVP_PKEY_EC) {
            return ECCONNECT_INVALID_PARAMETER;
        }
    } else {
        asym_ka_ctx->pkey = EVP_PKEY_new();
        if (!asym_ka_ctx->pkey) {
            return ECCONNECT_NO_MEMORY;
        }

        if (EVP_PKEY_set_type(asym_ka_ctx->pkey, EVP_PKEY_EC) != 1) {
            EVP_PKEY_free(asym_ka_ctx->pkey);
            asym_ka_ctx->pkey = NULL;
            return ECCONNECT_FAIL;
        }
    }

    switch (hdr->tag[0]) {
    case 'R':
        return ecconnect_ec_priv_key_to_engine_specific(hdr,
                                                    key_length,
                                                    ((ecconnect_engine_specific_ec_key_t**)&asym_ka_ctx->pkey));
    case 'U':
        return ecconnect_ec_pub_key_to_engine_specific(hdr,
                                                   key_length,
                                                   ((ecconnect_engine_specific_ec_key_t**)&asym_ka_ctx->pkey));
    default:
        return ECCONNECT_INVALID_PARAMETER;
    }
}

ecconnect_status_t ecconnect_asym_ka_export_key(ecconnect_asym_ka_t* asym_ka_ctx,
                                        void* key,
                                        size_t* key_length,
                                        bool isprivate)
{
    if (!asym_ka_ctx || !asym_ka_ctx->pkey) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    if (EVP_PKEY_base_id(asym_ka_ctx->pkey) != EVP_PKEY_EC) {
        return ECCONNECT_INVALID_PARAMETER;
    }

    if (isprivate) {
        return ecconnect_engine_specific_to_ec_priv_key((const ecconnect_engine_specific_ec_key_t*)
                                                        asym_ka_ctx->pkey,
                                                    (ecconnect_container_hdr_t*)key,
                                                    key_length);
    }

    return ecconnect_engine_specific_to_ec_pub_key((const ecconnect_engine_specific_ec_key_t*)asym_ka_ctx->pkey,
                                               true,
                                               (ecconnect_container_hdr_t*)key,
                                               key_length);
}

ecconnect_status_t ecconnect_asym_ka_derive(ecconnect_asym_ka_t* asym_ka_ctx,
                                    const void* peer_key,
                                    size_t peer_key_length,
                                    void* shared_secret,
                                    size_t* shared_secret_length)
{
    ecconnect_status_t res = ECCONNECT_FAIL;
    EVP_PKEY* peer_pkey = NULL;
    EVP_PKEY_CTX* derive_ctx = NULL;
    size_t out_length = 0;

    if (!asym_ka_ctx || !asym_ka_ctx->pkey) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    if (!peer_key || peer_key_length == 0 || !shared_secret_length) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    if (EVP_PKEY_base_id(asym_ka_ctx->pkey) != EVP_PKEY_EC) {
        return ECCONNECT_INVALID_PARAMETER;
    }

    peer_pkey = EVP_PKEY_new();
    if (NULL == peer_pkey) {
        return ECCONNECT_NO_MEMORY;
    }

    res = ecconnect_ec_pub_key_to_engine_specific((const ecconnect_container_hdr_t*)peer_key,
                                              peer_key_length,
                                              ((ecconnect_engine_specific_ec_key_t**)&peer_pkey));
    if (ECCONNECT_SUCCESS != res) {
        goto err;
    }

    derive_ctx = EVP_PKEY_CTX_new(asym_ka_ctx->pkey, NULL);
    if (!derive_ctx) {
        res = ECCONNECT_NO_MEMORY;
        goto err;
    }

    if (1 != EVP_PKEY_derive_init(derive_ctx)) {
        res = ECCONNECT_FAIL;
        goto err;
    }

    if (1 != EVP_PKEY_derive_set_peer(derive_ctx, peer_pkey)) {
        res = ECCONNECT_FAIL;
        goto err;
    }

    if (1 != EVP_PKEY_derive(derive_ctx, NULL, &out_length)) {
        res = ECCONNECT_FAIL;
        goto err;
    }

    if (!shared_secret || out_length > *shared_secret_length) {
        *shared_secret_length = out_length;
        res = ECCONNECT_BUFFER_TOO_SMALL;
        goto err;
    }

    if (1 != EVP_PKEY_derive(derive_ctx, (unsigned char*)shared_secret, shared_secret_length)) {
        res = ECCONNECT_FAIL;
        goto err;
    }

    res = ECCONNECT_SUCCESS;

err:
    EVP_PKEY_free(peer_pkey);
    EVP_PKEY_CTX_free(derive_ctx);

    return res;
}
