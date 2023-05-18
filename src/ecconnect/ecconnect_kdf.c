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

#include "ecconnect/ecconnect_kdf.h"

#include <string.h>

#include "ecconnect/ecconnect_t.h"
#include "ecconnect/ecconnect_wipe.h"

#define IMPLICIT_KEY_SIZE 32
#define MAX_HMAC_SIZE 64 /* For HMAC-SHA512 */
#define MIN_VAL(_X_, _Y_) (((_X_) < (_Y_)) ? (_X_) : (_Y_))

ecconnect_status_t ecconnect_kdf(const void* key,
                         size_t key_length,
                         const char* label,
                         const ecconnect_kdf_context_buf_t* context,
                         size_t context_count,
                         void* output,
                         size_t output_length)
{
    ecconnect_status_t res = ECCONNECT_SUCCESS;
    uint8_t implicit_key[IMPLICIT_KEY_SIZE] = {0};
    uint8_t out[MAX_HMAC_SIZE] = {0, 0, 0, 1};
    size_t out_length = sizeof(out);
    size_t label_length = 0;
    ecconnect_hmac_ctx_t* hmac_ctx = NULL;
    size_t i;
    size_t j;

    ECCONNECT_CHECK_PARAM(label != NULL);
    ECCONNECT_CHECK_PARAM(output != NULL);
    ECCONNECT_CHECK_PARAM(output_length != 0);
    if (key) {
        ECCONNECT_CHECK_PARAM(key_length != 0);
    } else {
        ECCONNECT_CHECK_PARAM(key_length == 0);
    }
    if (context_count > 0) {
        ECCONNECT_CHECK_PARAM(context != NULL);
    }

    label_length = strlen(label);

    /*
     * If key is not specified, we will generate it from other information
     * (useful for using ecconnect KDF for generating data from non-secret
     * parameters such as Session ID).
     *
     * This behavior is an extension of ecconnect KDF not specified by RFC 6189.
     */
    if (!key) {
        memset(implicit_key, 0, sizeof(implicit_key));

        memcpy(implicit_key, label, MIN_VAL(sizeof(implicit_key), label_length));

        for (i = 0; i < context_count; i++) {
            if (context[i].data) {
                for (j = 0; j < MIN_VAL(sizeof(implicit_key), context[i].length); j++) {
                    implicit_key[j] ^= context[i].data[j];
                }
            }
        }

        key = implicit_key;
        key_length = sizeof(implicit_key);
    }

    hmac_ctx = ecconnect_hmac_create(ECCONNECT_HASH_SHA256, key, key_length);
    if (!hmac_ctx) {
        return ECCONNECT_FAIL;
    }

    /* i (counter) */
    res = ecconnect_hmac_update(hmac_ctx, out, 4);
    if (ECCONNECT_SUCCESS != res) {
        goto err;
    }

    /* label */
    res = ecconnect_hmac_update(hmac_ctx, label, label_length);
    if (ECCONNECT_SUCCESS != res) {
        goto err;
    }

    /* 0x00 delimiter */
    res = ecconnect_hmac_update(hmac_ctx, out, 1);
    if (ECCONNECT_SUCCESS != res) {
        goto err;
    }

    /* context */
    for (i = 0; i < context_count; i++) {
        if (context[i].data) {
            res = ecconnect_hmac_update(hmac_ctx, context[i].data, context[i].length);
            if (ECCONNECT_SUCCESS != res) {
                goto err;
            }
        }
    }

    /*
     * Here RFC 6189 also appends "out_length" as big-endian 32-bit integer.
     * ecconnect KDF historically did not do this.
     */

    res = ecconnect_hmac_final(hmac_ctx, out, &out_length);
    if (ECCONNECT_SUCCESS != res) {
        goto err;
    }

    if (output_length > out_length) {
        res = ECCONNECT_INVALID_PARAMETER;
        goto err;
    }

    memcpy(output, out, output_length);

err:

    ecconnect_wipe(out, sizeof(out));
    ecconnect_wipe(implicit_key, sizeof(implicit_key));

    if (res != ECCONNECT_SUCCESS) {
        ecconnect_wipe(output, output_length);
    }

    ecconnect_hmac_destroy(hmac_ctx);

    return res;
}
