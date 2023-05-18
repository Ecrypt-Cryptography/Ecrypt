/*
 * Copyright (c) 2019 Cossack Labs Limited
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

#include "ecrypt/secure_keygen.h"

#include <stdlib.h>
#include <string.h>

#include "ecconnect/ecconnect_container.h"
#include "ecconnect/ecconnect_ec_key.h"
#include "ecconnect/ecconnect_rand.h"
#include "ecconnect/ecconnect_rsa_key.h"
#include "ecconnect/ecconnect_rsa_key_pair_gen.h"
#include "ecconnect/ecconnect_t.h"
#include "ecconnect/ecconnect_wipe.h"

#include "ecrypt/ecrypt_portable_endian.h"

#ifndef ECRYPT_RSA_KEY_LENGTH
#define ECRYPT_RSA_KEY_LENGTH RSA_KEY_LENGTH_2048
#endif

/*
 * This is the default key length recommended for use with Secure Cell.
 * It will have enough randomness for AES-256 (normally used by Ecrypt)
 * and is consistent with NIST recommendations for the next ten years,
 * as of 2020. See: https://www.keylength.com/en/4/
 */
#define ECRYPT_SYM_KEY_LENGTH 32

/*
 * Historically Ecrypt used compressed format for EC keys. This resulted
 * in a more compact representation, but is not optimal for performance.
 * Due to Hyrum's law, we can't change the default key format that easily,
 * so more efficient uncompressed representation can be used after opt-in.
 * (Note that we can import both representations without special actions.)
 */
static bool should_generate_compressed_ec_key_pairs(void)
{
    const char* uncompressed = getenv("ECRYPT_GEN_EC_KEY_PAIR_UNCOMPRESSED");
    if (uncompressed != NULL && strcmp(uncompressed, "1") == 0) {
        return false;
    }
    return true;
}

static ecrypt_status_t combine_key_generation_results(uint8_t* private_key,
                                                      const size_t* private_key_length,
                                                      ecrypt_status_t private_result,
                                                      uint8_t* public_key,
                                                      const size_t* public_key_length,
                                                      ecrypt_status_t public_result)
{
    if (private_result == ECRYPT_SUCCESS && public_result == ECRYPT_SUCCESS) {
        return ECRYPT_SUCCESS;
    }

    if (private_result != ECRYPT_BUFFER_TOO_SMALL) {
        ecconnect_wipe(private_key, *private_key_length);
    }
    if (public_result != ECRYPT_BUFFER_TOO_SMALL) {
        ecconnect_wipe(public_key, *public_key_length);
    }

    if (private_result == ECRYPT_BUFFER_TOO_SMALL || public_result == ECRYPT_BUFFER_TOO_SMALL) {
        return ECRYPT_BUFFER_TOO_SMALL;
    }

    return (private_result != ECRYPT_SUCCESS) ? private_result : public_result;
}

ecrypt_status_t ecrypt_gen_key_pair(ecconnect_sign_alg_t alg,
                                    uint8_t* private_key,
                                    size_t* private_key_length,
                                    uint8_t* public_key,
                                    size_t* public_key_length)
{
    ecrypt_status_t private_result = ECRYPT_FAIL;
    ecrypt_status_t public_result = ECRYPT_FAIL;
    ecconnect_sign_ctx_t* ctx = NULL;
    bool compressed = true;

    if (!private_key_length || !public_key_length) {
        return ECRYPT_INVALID_PARAMETER;
    }

    ctx = ecconnect_sign_create(alg, NULL, 0, NULL, 0);
    if (!ctx) {
        return ECRYPT_FAIL;
    }

    compressed = should_generate_compressed_ec_key_pairs();
    private_result = ecconnect_sign_export_private_key(ctx, private_key, private_key_length);
    public_result = ecconnect_sign_export_public_key(ctx, compressed, public_key, public_key_length);

    ecconnect_sign_destroy(ctx);

    return combine_key_generation_results(private_key,
                                          private_key_length,
                                          private_result,
                                          public_key,
                                          public_key_length,
                                          public_result);
}

ecrypt_status_t ecrypt_gen_rsa_key_pair(uint8_t* private_key,
                                        size_t* private_key_length,
                                        uint8_t* public_key,
                                        size_t* public_key_length)
{
    ecrypt_status_t private_result = ECRYPT_FAIL;
    ecrypt_status_t public_result = ECRYPT_FAIL;
    ecconnect_rsa_key_pair_gen_t* ctx = NULL;

    if (!private_key_length || !public_key_length) {
        return ECRYPT_INVALID_PARAMETER;
    }

    ctx = ecconnect_rsa_key_pair_gen_create(ECRYPT_RSA_KEY_LENGTH);
    if (!ctx) {
        return ECRYPT_FAIL;
    }

    private_result = ecconnect_rsa_key_pair_gen_export_key(ctx, private_key, private_key_length, true);
    public_result = ecconnect_rsa_key_pair_gen_export_key(ctx, public_key, public_key_length, false);

    ecconnect_rsa_key_pair_gen_destroy(ctx);

    return combine_key_generation_results(private_key,
                                          private_key_length,
                                          private_result,
                                          public_key,
                                          public_key_length,
                                          public_result);
}

ecrypt_status_t ecrypt_gen_ec_key_pair(uint8_t* private_key,
                                       size_t* private_key_length,
                                       uint8_t* public_key,
                                       size_t* public_key_length)
{
    return ecrypt_gen_key_pair(ECCONNECT_SIGN_ecdsa_none_pkcs8,
                               private_key,
                               private_key_length,
                               public_key,
                               public_key_length);
}

ecrypt_key_kind_t ecrypt_get_asym_key_kind(const uint8_t* key, size_t length)
{
    const ecconnect_container_hdr_t* container = (const void*)key;

    if (!key || (length < sizeof(ecconnect_container_hdr_t))) {
        return ECRYPT_KEY_INVALID;
    }

    if (!memcmp(container->tag, RSA_PRIV_KEY_PREF, strlen(RSA_PRIV_KEY_PREF))) {
        return ECRYPT_KEY_RSA_PRIVATE;
    }
    if (!memcmp(container->tag, RSA_PUB_KEY_PREF, strlen(RSA_PUB_KEY_PREF))) {
        return ECRYPT_KEY_RSA_PUBLIC;
    }
    if (!memcmp(container->tag, EC_PRIV_KEY_PREF, strlen(EC_PRIV_KEY_PREF))) {
        return ECRYPT_KEY_EC_PRIVATE;
    }
    if (!memcmp(container->tag, EC_PUB_KEY_PREF, strlen(EC_PUB_KEY_PREF))) {
        return ECRYPT_KEY_EC_PUBLIC;
    }

    return ECRYPT_KEY_INVALID;
}

ecrypt_status_t ecrypt_is_valid_asym_key(const uint8_t* key, size_t length)
{
    const ecconnect_container_hdr_t* container = (const void*)key;
    ecrypt_key_kind_t kind = ECRYPT_KEY_INVALID;

    if (!key || (length < sizeof(ecconnect_container_hdr_t))) {
        return ECRYPT_INVALID_PARAMETER;
    }

    kind = ecrypt_get_asym_key_kind(key, length);
    if (kind == ECRYPT_KEY_INVALID) {
        return ECRYPT_INVALID_PARAMETER;
    }
    if (length != be32toh(container->size)) {
        return ECRYPT_INVALID_PARAMETER;
    }
    if (ECCONNECT_SUCCESS != ecconnect_verify_container_checksum(container)) {
        return ECRYPT_DATA_CORRUPT;
    }

    switch (kind) {
    case ECRYPT_KEY_RSA_PRIVATE:
        return ecconnect_rsa_priv_key_check_length(container, length);
    case ECRYPT_KEY_RSA_PUBLIC:
        return ecconnect_rsa_pub_key_check_length(container, length);
    case ECRYPT_KEY_EC_PRIVATE:
        return ecconnect_ec_priv_key_check_length(container, length);
    case ECRYPT_KEY_EC_PUBLIC:
        return ecconnect_ec_pub_key_check_length(container, length);
    default:
        return ECRYPT_INVALID_PARAMETER;
    }

    return ECRYPT_INVALID_PARAMETER;
}

ecrypt_status_t ecrypt_gen_sym_key(uint8_t* key, size_t* key_length)
{
    if (key_length == NULL) {
        return ECRYPT_INVALID_PARAMETER;
    }

    if (key == NULL || *key_length == 0) {
        *key_length = ECRYPT_SYM_KEY_LENGTH;
        return ECRYPT_BUFFER_TOO_SMALL;
    }

    /* ecconnect_rand() wipes the key on failure, ecconnect_wipe() not needed */
    return ecconnect_rand(key, *key_length);
}
