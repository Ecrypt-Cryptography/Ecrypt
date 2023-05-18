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

#include "ecconnect/ecconnect_hash.h"

#include <openssl/evp.h>

#include "ecconnect/boringssl/ecconnect_engine.h"
#include "ecconnect/ecconnect_api.h"

static const EVP_MD* ecconnect_algo_to_evp_md(ecconnect_hash_algo_t algo)
{
    switch (algo) {
    case ECCONNECT_HASH_SHA256:
        return EVP_sha256();
    case ECCONNECT_HASH_SHA512:
        return EVP_sha512();
    default:
        return NULL;
    }
}

ECCONNECT_PRIVATE_API
ecconnect_status_t ecconnect_hash_init(ecconnect_hash_ctx_t* hash_ctx, ecconnect_hash_algo_t algo)
{
    const EVP_MD* md = ecconnect_algo_to_evp_md(algo);

    if (!hash_ctx || !md) {
        return ECCONNECT_INVALID_PARAMETER;
    }

    if (EVP_DigestInit(&(hash_ctx->evp_md_ctx), md)) {
        return ECCONNECT_SUCCESS;
    }

    return ECCONNECT_FAIL;
}

ecconnect_status_t ecconnect_hash_update(ecconnect_hash_ctx_t* hash_ctx, const void* data, size_t length)
{
    if (!hash_ctx || !data) {
        return ECCONNECT_INVALID_PARAMETER;
    }

    if (!EVP_MD_CTX_md(&(hash_ctx->evp_md_ctx))) {
        return ECCONNECT_INVALID_PARAMETER;
    }

    if (EVP_DigestUpdate(&(hash_ctx->evp_md_ctx), data, length)) {
        return ECCONNECT_SUCCESS;
    }

    return ECCONNECT_FAIL;
}

ecconnect_status_t ecconnect_hash_final(ecconnect_hash_ctx_t* hash_ctx, uint8_t* hash_value, size_t* hash_length)
{
    size_t md_length;

    if (!hash_ctx || !hash_length) {
        return ECCONNECT_INVALID_PARAMETER;
    }

    if (!EVP_MD_CTX_md(&(hash_ctx->evp_md_ctx))) {
        return ECCONNECT_INVALID_PARAMETER;
    }

    md_length = (size_t)EVP_MD_CTX_size(&(hash_ctx->evp_md_ctx));

    if (!hash_value || (md_length > *hash_length)) {
        *hash_length = md_length;
        return ECCONNECT_BUFFER_TOO_SMALL;
    }

    if (EVP_DigestFinal(&(hash_ctx->evp_md_ctx), hash_value, (unsigned int*)&md_length)) {
        *hash_length = md_length;
        return ECCONNECT_SUCCESS;
    }

    return ECCONNECT_FAIL;
}

ecconnect_hash_ctx_t* ecconnect_hash_create(ecconnect_hash_algo_t algo)
{
    ecconnect_status_t status;
    ecconnect_hash_ctx_t* ctx = malloc(sizeof(ecconnect_hash_ctx_t));
    if (!ctx) {
        return NULL;
    }

    status = ecconnect_hash_init(ctx, algo);
    if (ECCONNECT_SUCCESS == status) {
        return ctx;
    }

    free(ctx);
    return NULL;
}

ecconnect_status_t ecconnect_hash_cleanup(ecconnect_hash_ctx_t* hash_ctx)
{
    if (!hash_ctx) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    EVP_MD_CTX_cleanup(&(hash_ctx->evp_md_ctx));
    return ECCONNECT_SUCCESS;
}

ecconnect_status_t ecconnect_hash_destroy(ecconnect_hash_ctx_t* hash_ctx)
{
    if (!hash_ctx) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    EVP_MD_CTX_cleanup(&(hash_ctx->evp_md_ctx));
    free(hash_ctx);
    return ECCONNECT_SUCCESS;
}
