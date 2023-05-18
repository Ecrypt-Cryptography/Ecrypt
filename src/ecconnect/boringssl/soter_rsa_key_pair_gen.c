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

#include "ecconnect/ecconnect_rsa_key_pair_gen.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "ecconnect/boringssl/ecconnect_engine.h"
#include "ecconnect/boringssl/ecconnect_rsa_common.h"

ecconnect_rsa_key_pair_gen_t* ecconnect_rsa_key_pair_gen_create(const unsigned key_length)
{
    ECCONNECT_CHECK_PARAM_(rsa_key_length(key_length) > 0);
    ecconnect_rsa_key_pair_gen_t* ctx = malloc(sizeof(ecconnect_rsa_key_pair_gen_t));
    ECCONNECT_CHECK_MALLOC_(ctx);
    ECCONNECT_IF_FAIL_(ecconnect_rsa_key_pair_gen_init(ctx, key_length) == ECCONNECT_SUCCESS, free(ctx));
    return ctx;
}

ecconnect_status_t ecconnect_rsa_key_pair_gen_init(ecconnect_rsa_key_pair_gen_t* ctx, const unsigned key_length)
{
    ecconnect_status_t err = ECCONNECT_FAIL;
    EVP_PKEY* pkey = NULL;

    pkey = EVP_PKEY_new();
    if (!pkey) {
        return ECCONNECT_NO_MEMORY;
    }

    /* Only RSA supports asymmetric encryption */
    if (EVP_PKEY_set_type(pkey, EVP_PKEY_RSA) != 1) {
        goto free_pkey;
    }

    ctx->pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx->pkey_ctx) {
        err = ECCONNECT_NO_MEMORY;
        goto free_pkey;
    }

    err = ecconnect_rsa_gen_key(ctx->pkey_ctx, key_length);
    if (err != ECCONNECT_SUCCESS) {
        goto free_pkey_ctx;
    }

    EVP_PKEY_free(pkey);
    return ECCONNECT_SUCCESS;

free_pkey_ctx:
    EVP_PKEY_CTX_free(ctx->pkey_ctx);
    ctx->pkey_ctx = NULL;
free_pkey:
    EVP_PKEY_free(pkey);
    return err;
}

ecconnect_status_t ecconnect_rsa_key_pair_gen_cleanup(ecconnect_rsa_key_pair_gen_t* ctx)
{
    ECCONNECT_CHECK_PARAM(ctx);
    if (ctx->pkey_ctx) {
        EVP_PKEY_CTX_free(ctx->pkey_ctx);
        ctx->pkey_ctx = NULL;
    }
    return ECCONNECT_SUCCESS;
}

ecconnect_status_t ecconnect_rsa_key_pair_gen_destroy(ecconnect_rsa_key_pair_gen_t* ctx)
{
    ECCONNECT_CHECK_PARAM(ctx);
    ECCONNECT_CHECK(ecconnect_rsa_key_pair_gen_cleanup(ctx) == ECCONNECT_SUCCESS);
    free(ctx);
    return ECCONNECT_SUCCESS;
}

ecconnect_status_t ecconnect_rsa_key_pair_gen_export_key(ecconnect_rsa_key_pair_gen_t* ctx,
                                                 void* key,
                                                 size_t* key_length,
                                                 bool isprivate)
{
    EVP_PKEY* pkey;
    ECCONNECT_CHECK_PARAM(ctx);
    pkey = EVP_PKEY_CTX_get0_pkey(ctx->pkey_ctx);
    ECCONNECT_CHECK_PARAM(pkey);
    ECCONNECT_CHECK_PARAM(EVP_PKEY_RSA == EVP_PKEY_id(pkey));
    if (isprivate) {
        return ecconnect_engine_specific_to_rsa_priv_key((const ecconnect_engine_specific_rsa_key_t*)pkey,
                                                     (ecconnect_container_hdr_t*)key,
                                                     key_length);
    }

    return ecconnect_engine_specific_to_rsa_pub_key((const ecconnect_engine_specific_rsa_key_t*)pkey,
                                                (ecconnect_container_hdr_t*)key,
                                                key_length);
}
