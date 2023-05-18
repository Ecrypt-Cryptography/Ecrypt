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

#include "ecconnect/ecconnect_sign_ecdsa.h"
#include "ecconnect/ecconnect_sign_rsa.h"

#include "ecconnect/ecconnect_api.h"
#include "ecconnect/ecconnect_t.h"

ECCONNECT_PRIVATE_API
ecconnect_status_t ecconnect_sign_init(ecconnect_sign_ctx_t* ctx,
                               ecconnect_sign_alg_t algId,
                               const void* private_key,
                               const size_t private_key_length,
                               const void* public_key,
                               const size_t public_key_length)
{
    if (!ctx) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    ctx->alg = algId;
    switch (ctx->alg) {
    case ECCONNECT_SIGN_rsa_pss_pkcs8:
        return ecconnect_sign_init_rsa_pss_pkcs8(ctx, private_key, private_key_length, public_key, public_key_length);
    case ECCONNECT_SIGN_ecdsa_none_pkcs8:
        return ecconnect_sign_init_ecdsa_none_pkcs8(ctx,
                                                private_key,
                                                private_key_length,
                                                public_key,
                                                public_key_length);
    default:
        return ECCONNECT_INVALID_PARAMETER;
    }
    return ECCONNECT_INVALID_PARAMETER;
}

ECCONNECT_PRIVATE_API
ecconnect_status_t ecconnect_verify_init(ecconnect_sign_ctx_t* ctx,
                                 ecconnect_sign_alg_t algId,
                                 const void* private_key,
                                 const size_t private_key_length,
                                 const void* public_key,
                                 const size_t public_key_length)
{
    if (!ctx) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    ctx->alg = algId;
    switch (ctx->alg) {
    case ECCONNECT_SIGN_rsa_pss_pkcs8:
        return ecconnect_verify_init_rsa_pss_pkcs8(ctx,
                                               private_key,
                                               private_key_length,
                                               public_key,
                                               public_key_length);
    case ECCONNECT_SIGN_ecdsa_none_pkcs8:
        return ecconnect_verify_init_ecdsa_none_pkcs8(ctx,
                                                  private_key,
                                                  private_key_length,
                                                  public_key,
                                                  public_key_length);
    default:
        return ECCONNECT_INVALID_PARAMETER;
    }
    return ECCONNECT_INVALID_PARAMETER;
}

ecconnect_status_t ecconnect_sign_export_key(ecconnect_sign_ctx_t* ctx, void* key, size_t* key_length, bool isprivate)
{
    if (!ctx) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    switch (ctx->alg) {
    case ECCONNECT_SIGN_rsa_pss_pkcs8:
        return ecconnect_sign_export_key_rsa_pss_pkcs8(ctx, key, key_length, isprivate);
    case ECCONNECT_SIGN_ecdsa_none_pkcs8:
        if (isprivate) {
            return ecconnect_sign_export_private_key_ecdsa_none_pkcs8(ctx, key, key_length);
        } else {
            return ecconnect_sign_export_public_key_ecdsa_none_pkcs8(ctx, true, key, key_length);
        }
    default:
        return ECCONNECT_INVALID_PARAMETER;
    }
    return ECCONNECT_INVALID_PARAMETER;
}

ecconnect_status_t ecconnect_sign_export_private_key(const ecconnect_sign_ctx_t* ctx, void* key, size_t* key_length)
{
    if (!ctx) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    switch (ctx->alg) {
    case ECCONNECT_SIGN_rsa_pss_pkcs8:
        return ecconnect_sign_export_key_rsa_pss_pkcs8(ctx, key, key_length, true);
    case ECCONNECT_SIGN_ecdsa_none_pkcs8:
        return ecconnect_sign_export_private_key_ecdsa_none_pkcs8(ctx, key, key_length);
    default:
        return ECCONNECT_INVALID_PARAMETER;
    }
    return ECCONNECT_INVALID_PARAMETER;
}

ecconnect_status_t ecconnect_sign_export_public_key(const ecconnect_sign_ctx_t* ctx,
                                            bool compressed,
                                            void* key,
                                            size_t* key_length)
{
    if (!ctx) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    switch (ctx->alg) {
    case ECCONNECT_SIGN_rsa_pss_pkcs8:
        return ecconnect_sign_export_key_rsa_pss_pkcs8(ctx, key, key_length, false);
    case ECCONNECT_SIGN_ecdsa_none_pkcs8:
        return ecconnect_sign_export_public_key_ecdsa_none_pkcs8(ctx, compressed, key, key_length);
    default:
        return ECCONNECT_INVALID_PARAMETER;
    }
    return ECCONNECT_INVALID_PARAMETER;
}

ecconnect_status_t ecconnect_sign_update(ecconnect_sign_ctx_t* ctx, const void* data, const size_t data_length)
{
    if (!ctx || !data || !data_length) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    switch (ctx->alg) {
    case ECCONNECT_SIGN_rsa_pss_pkcs8:
        return ecconnect_sign_update_rsa_pss_pkcs8(ctx, data, data_length);
    case ECCONNECT_SIGN_ecdsa_none_pkcs8:
        return ecconnect_sign_update_ecdsa_none_pkcs8(ctx, data, data_length);
    default:
        return ECCONNECT_INVALID_PARAMETER;
    }
    return ECCONNECT_INVALID_PARAMETER;
}

ecconnect_status_t ecconnect_verify_update(ecconnect_sign_ctx_t* ctx, const void* data, const size_t data_length)
{
    if (!ctx || !data || !data_length) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    switch (ctx->alg) {
    case ECCONNECT_SIGN_rsa_pss_pkcs8:
        return ecconnect_verify_update_rsa_pss_pkcs8(ctx, data, data_length);
    case ECCONNECT_SIGN_ecdsa_none_pkcs8:
        return ecconnect_verify_update_ecdsa_none_pkcs8(ctx, data, data_length);
    default:
        return ECCONNECT_INVALID_PARAMETER;
    }
    return ECCONNECT_INVALID_PARAMETER;
}

ecconnect_status_t ecconnect_sign_final(ecconnect_sign_ctx_t* ctx, void* signature, size_t* signature_length)
{
    if (!ctx) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    switch (ctx->alg) {
    case ECCONNECT_SIGN_rsa_pss_pkcs8:
        return ecconnect_sign_final_rsa_pss_pkcs8(ctx, signature, signature_length);
    case ECCONNECT_SIGN_ecdsa_none_pkcs8:
        return ecconnect_sign_final_ecdsa_none_pkcs8(ctx, signature, signature_length);
    default:
        return ECCONNECT_INVALID_PARAMETER;
    }
    return ECCONNECT_INVALID_PARAMETER;
}

ecconnect_status_t ecconnect_verify_final(ecconnect_sign_ctx_t* ctx, const void* signature, const size_t signature_length)
{
    if (!ctx || !signature || !signature_length) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    switch (ctx->alg) {
    case ECCONNECT_SIGN_rsa_pss_pkcs8:
        return ecconnect_verify_final_rsa_pss_pkcs8(ctx, signature, signature_length);
    case ECCONNECT_SIGN_ecdsa_none_pkcs8:
        return ecconnect_verify_final_ecdsa_none_pkcs8(ctx, signature, signature_length);
    default:
        return ECCONNECT_INVALID_PARAMETER;
    }
    return ECCONNECT_INVALID_PARAMETER;
}

ecconnect_status_t ecconnect_sign_cleanup(ecconnect_sign_ctx_t* ctx)
{
    if (!ctx) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    switch (ctx->alg) {
    case ECCONNECT_SIGN_rsa_pss_pkcs8:
        return ecconnect_sign_cleanup_rsa_pss_pkcs8(ctx);
    case ECCONNECT_SIGN_ecdsa_none_pkcs8:
        return ecconnect_sign_cleanup_ecdsa_none_pkcs8(ctx);
    default:
        return ECCONNECT_INVALID_PARAMETER;
    }
    return ECCONNECT_INVALID_PARAMETER;
}

ecconnect_status_t ecconnect_verify_cleanup(ecconnect_sign_ctx_t* ctx)
{
    if (!ctx) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    switch (ctx->alg) {
    case ECCONNECT_SIGN_rsa_pss_pkcs8:
        return ecconnect_verify_cleanup_rsa_pss_pkcs8(ctx);
    case ECCONNECT_SIGN_ecdsa_none_pkcs8:
        return ecconnect_verify_cleanup_ecdsa_none_pkcs8(ctx);
    default:
        return ECCONNECT_INVALID_PARAMETER;
    }
    return ECCONNECT_INVALID_PARAMETER;
}

ecconnect_sign_ctx_t* ecconnect_sign_create(ecconnect_sign_alg_t alg,
                                    const void* private_key,
                                    const size_t private_key_length,
                                    const void* public_key,
                                    const size_t public_key_length)
{
    ecconnect_sign_ctx_t* ctx = calloc(sizeof(ecconnect_sign_ctx_t), 1);
    if (!ctx) {
        return NULL;
    }
    if (ecconnect_sign_init(ctx, alg, private_key, private_key_length, public_key, public_key_length)
        != ECCONNECT_SUCCESS) {
        ecconnect_sign_cleanup(ctx);
        free(ctx);
        return NULL;
    }
    return ctx;
}

ecconnect_sign_ctx_t* ecconnect_verify_create(ecconnect_sign_alg_t alg,
                                      const void* private_key,
                                      const size_t private_key_length,
                                      const void* public_key,
                                      const size_t public_key_length)
{
    ecconnect_sign_ctx_t* ctx = calloc(sizeof(ecconnect_sign_ctx_t), 1);
    if (!ctx) {
        return NULL;
    }
    if (ecconnect_verify_init(ctx, alg, private_key, private_key_length, public_key, public_key_length)
        != ECCONNECT_SUCCESS) {
        ecconnect_verify_destroy(ctx);
        return NULL;
    }
    return ctx;
}

ecconnect_status_t ecconnect_sign_destroy(ecconnect_sign_ctx_t* ctx)
{
    if (!ctx) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    ecconnect_sign_cleanup(ctx);
    free(ctx);
    return ECCONNECT_SUCCESS;
}

ecconnect_status_t ecconnect_verify_destroy(ecconnect_sign_ctx_t* ctx)
{
    if (!ctx) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    ecconnect_verify_cleanup(ctx);
    free(ctx);
    return ECCONNECT_SUCCESS;
}

ecconnect_sign_alg_t ecconnect_sign_get_alg_id(ecconnect_sign_ctx_t* ctx)
{
    if (!ctx) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    return ctx->alg;
}

ecconnect_sign_alg_t ecconnect_verify_get_alg_id(ecconnect_verify_ctx_t* ctx)
{
    if (!ctx) {
        return ECCONNECT_INVALID_PARAMETER;
    }
    return ctx->alg;
}
