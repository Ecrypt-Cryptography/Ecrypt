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

#include "ecconnect/boringssl/ecconnect_engine.h"
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
    ecconnect_status_t err = ECCONNECT_FAIL;
    EVP_PKEY* pkey = NULL;
    EC_KEY* ec = NULL;
    int nid = ecconnect_alg_to_curve_nid(alg);

    if ((!asym_ka_ctx) || (0 == nid)) {
        return ECCONNECT_INVALID_PARAMETER;
    }

    pkey = EVP_PKEY_new();
    if (!pkey) {
        return ECCONNECT_NO_MEMORY;
    }

    if (!EVP_PKEY_set_type(pkey, EVP_PKEY_EC)) {
        goto free_pkey;
    }

    asym_ka_ctx->pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!(asym_ka_ctx->pkey_ctx)) {
        err = ECCONNECT_NO_MEMORY;
        goto free_pkey;
    }

    ec = EC_KEY_new_by_curve_name(nid);
    if (!ec) {
        goto free_pkey_ctx;
    }

    if (EVP_PKEY_assign_EC_KEY(pkey, ec) != 1) {
        goto free_ec_key;
    }

    EVP_PKEY_free(pkey);
    return ECCONNECT_SUCCESS;

free_ec_key:
    EC_KEY_free(ec);
free_pkey_ctx:
    EVP_PKEY_CTX_free(asym_ka_ctx->pkey_ctx);
    asym_ka_ctx->pkey_ctx = NULL;
free_pkey:
    EVP_PKEY_free(pkey);
    return err;
}

ECCONNECT_PRIVATE_API
ecconnect_status_t ecconnect_asym_ka_cleanup(ecconnect_asym_ka_t* asym_ka_ctx)
{
    if (!asym_ka_ctx) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    if (asym_ka_ctx->pkey_ctx) {
        EVP_PKEY_CTX_free(asym_ka_ctx->pkey_ctx);
        asym_ka_ctx->pkey_ctx = NULL;
    }
    return ECCONNECT_SUCCESS;
}

ecconnect_asym_ka_t* ecconnect_asym_ka_create(ecconnect_asym_ka_alg_t alg)
{
    ecconnect_status_t status;
    ecconnect_asym_ka_t* ctx = malloc(sizeof(ecconnect_asym_ka_t));
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
    EVP_PKEY* pkey;
    EC_KEY* ec;

    if (!asym_ka_ctx) {
        return ECCONNECT_INVALID_PARAMETER;
    }

    pkey = EVP_PKEY_CTX_get0_pkey(asym_ka_ctx->pkey_ctx);

    if (!pkey) {
        return ECCONNECT_INVALID_PARAMETER;
    }

    if (EVP_PKEY_EC != EVP_PKEY_id(pkey)) {
        return ECCONNECT_INVALID_PARAMETER;
    }

    ec = EVP_PKEY_get0_EC_KEY(pkey);
    if (NULL == ec) {
        return ECCONNECT_INVALID_PARAMETER;
    }

    if (1 == EC_KEY_generate_key(ec)) {
        return ECCONNECT_SUCCESS;
    }

    return ECCONNECT_FAIL;
}

ecconnect_status_t ecconnect_asym_ka_import_key(ecconnect_asym_ka_t* asym_ka_ctx, const void* key, size_t key_length)
{
    const ecconnect_container_hdr_t* hdr = key;
    EVP_PKEY* pkey;

    if ((!asym_ka_ctx) || (!key)) {
        return ECCONNECT_INVALID_PARAMETER;
    }

    if (key_length < sizeof(ecconnect_container_hdr_t)) {
        return ECCONNECT_INVALID_PARAMETER;
    }

    pkey = EVP_PKEY_CTX_get0_pkey(asym_ka_ctx->pkey_ctx);

    if (!pkey) {
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
    default:
        return ECCONNECT_INVALID_PARAMETER;
    }
}

ecconnect_status_t ecconnect_asym_ka_export_key(ecconnect_asym_ka_t* asym_ka_ctx,
                                        void* key,
                                        size_t* key_length,
                                        bool isprivate)
{
    EVP_PKEY* pkey;

    if (!asym_ka_ctx) {
        return ECCONNECT_INVALID_PARAMETER;
    }

    pkey = EVP_PKEY_CTX_get0_pkey(asym_ka_ctx->pkey_ctx);

    if (!pkey) {
        return ECCONNECT_INVALID_PARAMETER;
    }

    if (EVP_PKEY_EC != EVP_PKEY_id(pkey)) {
        return ECCONNECT_INVALID_PARAMETER;
    }

    if (isprivate) {
        return ecconnect_engine_specific_to_ec_priv_key((const ecconnect_engine_specific_ec_key_t*)pkey,
                                                    (ecconnect_container_hdr_t*)key,
                                                    key_length);
    }

    return ecconnect_engine_specific_to_ec_pub_key((const ecconnect_engine_specific_ec_key_t*)pkey,
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
    EVP_PKEY* peer_pkey = EVP_PKEY_new();
    ecconnect_status_t res;
    size_t out_length;

    if (NULL == peer_pkey) {
        return ECCONNECT_NO_MEMORY;
    }

    if ((!asym_ka_ctx) || (!shared_secret_length)) {
        EVP_PKEY_free(peer_pkey);
        return ECCONNECT_INVALID_PARAMETER;
    }

    res = ecconnect_ec_pub_key_to_engine_specific((const ecconnect_container_hdr_t*)peer_key,
                                              peer_key_length,
                                              ((ecconnect_engine_specific_ec_key_t**)&peer_pkey));
    if (ECCONNECT_SUCCESS != res) {
        EVP_PKEY_free(peer_pkey);
        return res;
    }

    if (1 != EVP_PKEY_derive_init(asym_ka_ctx->pkey_ctx)) {
        EVP_PKEY_free(peer_pkey);
        return ECCONNECT_FAIL;
    }

    if (1 != EVP_PKEY_derive_set_peer(asym_ka_ctx->pkey_ctx, peer_pkey)) {
        EVP_PKEY_free(peer_pkey);
        return ECCONNECT_FAIL;
    }

    if (1 != EVP_PKEY_derive(asym_ka_ctx->pkey_ctx, NULL, &out_length)) {
        EVP_PKEY_free(peer_pkey);
        return ECCONNECT_FAIL;
    }

    if (out_length > *shared_secret_length) {
        EVP_PKEY_free(peer_pkey);
        *shared_secret_length = out_length;
        return ECCONNECT_BUFFER_TOO_SMALL;
    }

    if (1 != EVP_PKEY_derive(asym_ka_ctx->pkey_ctx, (unsigned char*)shared_secret, shared_secret_length)) {
        EVP_PKEY_free(peer_pkey);
        return ECCONNECT_FAIL;
    }

    EVP_PKEY_free(peer_pkey);
    return ECCONNECT_SUCCESS;
}
