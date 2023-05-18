/*
 * Copyright (c) 2020 Cossack Labs Limited
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

#include "ecrypt/secure_cell_seal_passphrase.h"

#include "ecconnect/ecconnect_kdf.h"
#include "ecconnect/ecconnect_rand.h"
#include "ecconnect/ecconnect_wipe.h"

#include "ecrypt/secure_cell_alg.h"
#include "ecrypt/sym_enc_message.h"

/*
 * Ecrypt always uses the default algorithm and parameters for encryption.
 * These may be transparently updated between library releases. However,
 * decryption code has to support all previously produces data formats.
 */

static inline uint32_t ecconnect_alg_without_kdf(uint32_t alg)
{
    /* Explicit cast for mask to have correct size before negation */
    return (alg & ~((uint32_t)ECCONNECT_SYM_KDF_MASK)) | ECCONNECT_SYM_NOKDF;
}

static inline size_t ecconnect_alg_kdf_context_length(uint32_t alg)
{
    switch (ecconnect_alg_kdf(alg)) {
    case ECCONNECT_SYM_PBKDF2:
        return ecrypt_scell_pbkdf2_context_min_size + ECRYPT_AUTH_SYM_PBKDF2_SALT_LENGTH;
    case ECCONNECT_SYM_NOKDF:
        return 0;
    default:
        return 0;
    }
}

static inline size_t default_auth_token_size(void)
{
    return ecrypt_scell_auth_token_passphrase_min_size + ECRYPT_AUTH_SYM_IV_LENGTH
           + ECRYPT_AUTH_SYM_AUTH_TAG_LENGTH
           + ecconnect_alg_kdf_context_length(ECRYPT_AUTH_SYM_PASSPHRASE_ALG);
}

static ecrypt_status_t ecrypt_auth_sym_derive_encryption_key_pbkdf2(
    struct ecrypt_scell_auth_token_passphrase* hdr,
    const uint8_t* passphrase,
    size_t passphrase_length,
    const uint8_t* user_context,
    size_t user_context_length,
    size_t message_length,
    uint8_t* derived_key,
    size_t* derived_key_length,
    uint8_t* auth_token,
    size_t* auth_token_length)
{
    ecrypt_status_t res = ECRYPT_FAIL;
    uint8_t salt[ECRYPT_AUTH_SYM_PBKDF2_SALT_LENGTH] = {0};
    uint8_t prekey[ECRYPT_AUTH_SYM_MAX_KEY_LENGTH / 8] = {0};
    uint8_t ecconnect_kdf_context[ECRYPT_AUTH_SYM_MAX_KDF_CONTEXT_LENGTH] = {0};
    size_t ecconnect_kdf_context_length = sizeof(ecconnect_kdf_context);
    struct ecrypt_scell_pbkdf2_context kdf;

    memset(&kdf, 0, sizeof(kdf));
    kdf.iteration_count = ECRYPT_AUTH_SYM_PBKDF2_ITERATIONS;
    kdf.salt = salt;
    kdf.salt_length = sizeof(salt);

    if (*auth_token_length < ecrypt_scell_pbkdf2_context_size(&kdf)) {
        *auth_token_length = ecrypt_scell_pbkdf2_context_size(&kdf);
        return ECRYPT_BUFFER_TOO_SMALL;
    }

    res = ecconnect_rand(salt, sizeof(salt));
    if (res != ECRYPT_SUCCESS) {
        goto error;
    }

    res = ecconnect_pbkdf2_sha256(passphrase,
                              passphrase_length,
                              kdf.salt,
                              kdf.salt_length,
                              kdf.iteration_count,
                              prekey,
                              sizeof(prekey));
    if (res != ECRYPT_SUCCESS) {
        goto error;
    }

    /*
     * ecrypt_auth_sym_encrypt_message_with_passphrase_() makes sure that
     * message_length fits into uint32_t.
     */
    res = ecrypt_auth_sym_kdf_context((uint32_t)message_length,
                                      ecconnect_kdf_context,
                                      &ecconnect_kdf_context_length);
    if (res != ECRYPT_SUCCESS) {
        goto error;
    }

    /* Use ecconnect KDF to derive key from prekey */
    res = ecrypt_auth_sym_derive_encryption_key(ecconnect_alg_without_kdf(hdr->alg),
                                                prekey,
                                                sizeof(prekey),
                                                ecconnect_kdf_context,
                                                ecconnect_kdf_context_length,
                                                user_context,
                                                user_context_length,
                                                derived_key,
                                                derived_key_length);
    if (res != ECRYPT_SUCCESS) {
        goto error;
    }

    /* KDF pointer is ignored but size is important */
    hdr->kdf_context = NULL;
    hdr->kdf_context_length = ecrypt_scell_pbkdf2_context_size(&kdf);

    res = ecrypt_write_scell_pbkdf2_context(hdr, &kdf, auth_token, *auth_token_length);
    if (res != ECRYPT_SUCCESS) {
        goto error;
    }

error:
    ecconnect_wipe(salt, sizeof(salt));
    ecconnect_wipe(prekey, sizeof(prekey));

    return res;
}

static ecrypt_status_t ecrypt_auth_sym_derive_encryption_key_passphrase(
    struct ecrypt_scell_auth_token_passphrase* hdr,
    const uint8_t* passphrase,
    size_t passphrase_length,
    const uint8_t* user_context,
    size_t user_context_length,
    size_t message_length,
    uint8_t* derived_key,
    size_t* derived_key_length,
    uint8_t* auth_token,
    size_t* auth_token_length)
{
    switch (ecconnect_alg_kdf(hdr->alg)) {
    case ECCONNECT_SYM_PBKDF2:
        return ecrypt_auth_sym_derive_encryption_key_pbkdf2(hdr,
                                                            passphrase,
                                                            passphrase_length,
                                                            user_context,
                                                            user_context_length,
                                                            message_length,
                                                            derived_key,
                                                            derived_key_length,
                                                            auth_token,
                                                            auth_token_length);
    case ECCONNECT_SYM_NOKDF:
        return ECRYPT_FAIL;
    default:
        return ECRYPT_FAIL;
    }
}

ecrypt_status_t ecrypt_auth_sym_encrypt_message_with_passphrase_(const uint8_t* passphrase,
                                                                 size_t passphrase_length,
                                                                 const uint8_t* message,
                                                                 size_t message_length,
                                                                 const uint8_t* user_context,
                                                                 size_t user_context_length,
                                                                 uint8_t* auth_token,
                                                                 size_t* auth_token_length,
                                                                 uint8_t* encrypted_message,
                                                                 size_t* encrypted_message_length)
{
    ecrypt_status_t res = ECRYPT_FAIL;
    uint8_t iv[ECRYPT_AUTH_SYM_IV_LENGTH] = {0};
    uint8_t auth_tag[ECRYPT_AUTH_SYM_AUTH_TAG_LENGTH] = {0};
    uint8_t derived_key[ECRYPT_AUTH_SYM_KEY_LENGTH / 8] = {0};
    size_t derived_key_length = sizeof(derived_key);
    size_t auth_token_real_length = 0;
    struct ecrypt_scell_auth_token_passphrase hdr;

    /* Message length is currently stored as 32-bit integer, sorry */
    if (message_length > UINT32_MAX) {
        return ECRYPT_INVALID_PARAMETER;
    }

    memset(&hdr, 0, sizeof(hdr));
    hdr.alg = ECRYPT_AUTH_SYM_PASSPHRASE_ALG;
    hdr.iv = iv;
    hdr.iv_length = sizeof(iv);
    hdr.auth_tag = auth_tag;
    hdr.auth_tag_length = sizeof(auth_tag);
    hdr.message_length = (uint32_t)message_length;

    res = ecrypt_auth_sym_derive_encryption_key_passphrase(&hdr,
                                                           passphrase,
                                                           passphrase_length,
                                                           user_context,
                                                           user_context_length,
                                                           message_length,
                                                           derived_key,
                                                           &derived_key_length,
                                                           auth_token,
                                                           auth_token_length);
    if (res != ECRYPT_SUCCESS) {
        goto error;
    }

    res = ecconnect_rand(iv, sizeof(iv));
    if (res != ECRYPT_SUCCESS) {
        goto error;
    }

    /* We are doing KDF ourselves, ask ecconnect to not interfere */
    res = ecrypt_auth_sym_plain_encrypt(ecconnect_alg_without_kdf(hdr.alg),
                                        derived_key,
                                        derived_key_length,
                                        hdr.iv,
                                        hdr.iv_length,
                                        user_context,
                                        user_context_length,
                                        message,
                                        message_length,
                                        encrypted_message,
                                        encrypted_message_length,
                                        &auth_tag[0],
                                        &hdr.auth_tag_length);
    if (res != ECRYPT_SUCCESS) {
        goto error;
    }

    /* In valid Secure Cells auth token length always fits into uint32_t. */
    auth_token_real_length = (uint32_t)ecrypt_scell_auth_token_passphrase_size(&hdr);

    if (*auth_token_length < auth_token_real_length) {
        *auth_token_length = auth_token_real_length;
        res = ECRYPT_BUFFER_TOO_SMALL;
        goto error;
    }
    res = ecrypt_write_scell_auth_token_passphrase(&hdr, auth_token, *auth_token_length);
    if (res != ECRYPT_SUCCESS) {
        goto error;
    }
    *auth_token_length = auth_token_real_length;
    *encrypted_message_length = message_length;

error:
    ecconnect_wipe(iv, sizeof(iv));
    ecconnect_wipe(auth_tag, sizeof(auth_tag));
    ecconnect_wipe(derived_key, sizeof(derived_key));

    return res;
}

ecrypt_status_t ecrypt_auth_sym_encrypt_message_with_passphrase(const uint8_t* passphrase,
                                                                size_t passphrase_length,
                                                                const uint8_t* message,
                                                                size_t message_length,
                                                                const uint8_t* user_context,
                                                                size_t user_context_length,
                                                                uint8_t* auth_token,
                                                                size_t* auth_token_length,
                                                                uint8_t* encrypted_message,
                                                                size_t* encrypted_message_length)
{
    ECRYPT_CHECK_PARAM(passphrase != NULL && passphrase_length != 0);
    ECRYPT_CHECK_PARAM(message != NULL && message_length != 0);
    if (user_context_length != 0) {
        ECRYPT_CHECK_PARAM(user_context != NULL);
    }
    ECRYPT_CHECK_PARAM(auth_token_length != NULL);
    ECRYPT_CHECK_PARAM(encrypted_message_length != NULL);

    if (!auth_token_length || !encrypted_message || *auth_token_length < default_auth_token_size()
        || *encrypted_message_length < message_length) {
        *auth_token_length = default_auth_token_size();
        *encrypted_message_length = message_length;
        return ECRYPT_BUFFER_TOO_SMALL;
    }

    return ecrypt_auth_sym_encrypt_message_with_passphrase_(passphrase,
                                                            passphrase_length,
                                                            message,
                                                            message_length,
                                                            user_context,
                                                            user_context_length,
                                                            auth_token,
                                                            auth_token_length,
                                                            encrypted_message,
                                                            encrypted_message_length);
}

static ecrypt_status_t ecrypt_auth_sym_derive_decryption_key_pbkdf2(
    const struct ecrypt_scell_auth_token_passphrase* hdr,
    const uint8_t* passphrase,
    size_t passphrase_length,
    const uint8_t* user_context,
    size_t user_context_length,
    size_t message_length,
    uint8_t* derived_key,
    size_t* derived_key_length)
{
    ecrypt_status_t res = ECRYPT_FAIL;
    uint8_t prekey[ECRYPT_AUTH_SYM_MAX_KEY_LENGTH / 8] = {0};
    uint8_t ecconnect_kdf_context[ECRYPT_AUTH_SYM_MAX_KDF_CONTEXT_LENGTH] = {0};
    size_t ecconnect_kdf_context_length = sizeof(ecconnect_kdf_context);
    struct ecrypt_scell_pbkdf2_context kdf;

    memset(&kdf, 0, sizeof(kdf));
    res = ecrypt_read_scell_pbkdf2_context(hdr, &kdf);
    if (res != ECRYPT_SUCCESS) {
        return res;
    }

    res = ecconnect_pbkdf2_sha256(passphrase,
                              passphrase_length,
                              kdf.salt,
                              kdf.salt_length,
                              kdf.iteration_count,
                              prekey,
                              sizeof(prekey));
    if (res != ECRYPT_SUCCESS) {
        goto error;
    }

    /*
     * ecrypt_auth_sym_decrypt_message_with_passphrase_() makes sure that
     * message_length fits into uint32_t.
     */
    res = ecrypt_auth_sym_kdf_context((uint32_t)message_length,
                                      ecconnect_kdf_context,
                                      &ecconnect_kdf_context_length);
    if (res != ECRYPT_SUCCESS) {
        goto error;
    }

    /* Use ecconnect KDF to derive key from prekey */
    res = ecrypt_auth_sym_derive_encryption_key(ecconnect_alg_without_kdf(hdr->alg),
                                                prekey,
                                                sizeof(prekey),
                                                ecconnect_kdf_context,
                                                ecconnect_kdf_context_length,
                                                user_context,
                                                user_context_length,
                                                derived_key,
                                                derived_key_length);
    if (res != ECRYPT_SUCCESS) {
        goto error;
    }

error:
    ecconnect_wipe(prekey, sizeof(prekey));

    return res;
}

static ecrypt_status_t ecrypt_auth_sym_derive_decryption_key_passphrase(
    const struct ecrypt_scell_auth_token_passphrase* hdr,
    const uint8_t* passphrase,
    size_t passphrase_length,
    const uint8_t* user_context,
    size_t user_context_length,
    size_t message_length,
    uint8_t* derived_key,
    size_t* derived_key_length)
{
    switch (ecconnect_alg_kdf(hdr->alg)) {
    case ECCONNECT_SYM_PBKDF2:
        return ecrypt_auth_sym_derive_decryption_key_pbkdf2(hdr,
                                                            passphrase,
                                                            passphrase_length,
                                                            user_context,
                                                            user_context_length,
                                                            message_length,
                                                            derived_key,
                                                            derived_key_length);
    case ECCONNECT_SYM_NOKDF:
        return ECRYPT_FAIL;
    default:
        return ECRYPT_FAIL;
    }
}

ecrypt_status_t ecrypt_auth_sym_decrypt_message_with_passphrase_(const uint8_t* passphrase,
                                                                 size_t passphrase_length,
                                                                 const uint8_t* user_context,
                                                                 size_t user_context_length,
                                                                 const uint8_t* auth_token,
                                                                 size_t auth_token_length,
                                                                 const uint8_t* encrypted_message,
                                                                 size_t encrypted_message_length,
                                                                 uint8_t* message,
                                                                 size_t* message_length)
{
    ecrypt_status_t res = ECRYPT_FAIL;
    struct ecrypt_scell_auth_token_passphrase hdr;
    /* Use maximum possible length, not the default one */
    uint8_t derived_key[ECRYPT_AUTH_SYM_MAX_KEY_LENGTH / 8] = {0};
    size_t derived_key_length = sizeof(derived_key);

    memset(&hdr, 0, sizeof(hdr));
    res = ecrypt_read_scell_auth_token_passphrase(auth_token, auth_token_length, &hdr);
    if (res != ECRYPT_SUCCESS) {
        return res;
    }

    /* Check that message length is consistent with header */
    if (hdr.message_length != encrypted_message_length) {
        return ECRYPT_FAIL;
    }
    /* Algorithm field contains unused bits that must be set to zero */
    if (!ecconnect_alg_reserved_bits_valid(hdr.alg)) {
        return ECRYPT_FAIL;
    }

    res = ecrypt_auth_sym_derive_decryption_key_passphrase(&hdr,
                                                           passphrase,
                                                           passphrase_length,
                                                           user_context,
                                                           user_context_length,
                                                           encrypted_message_length,
                                                           &derived_key[0],
                                                           &derived_key_length);
    if (res != ECRYPT_SUCCESS) {
        return res;
    }

    /* We are doing KDF ourselves, ask ecconnect to not interfere */
    res = ecrypt_auth_sym_plain_decrypt(ecconnect_alg_without_kdf(hdr.alg),
                                        derived_key,
                                        derived_key_length,
                                        hdr.iv,
                                        hdr.iv_length,
                                        user_context,
                                        user_context_length,
                                        encrypted_message,
                                        encrypted_message_length,
                                        message,
                                        message_length,
                                        hdr.auth_tag,
                                        hdr.auth_tag_length);
    /* Sanity check of resulting message length */
    if (*message_length != encrypted_message_length) {
        res = ECRYPT_FAIL;
        goto error;
    }

error:
    ecconnect_wipe(derived_key, sizeof(derived_key));

    return res;
}

ecrypt_status_t ecrypt_auth_sym_decrypt_message_with_passphrase(const uint8_t* passphrase,
                                                                size_t passphrase_length,
                                                                const uint8_t* user_context,
                                                                size_t user_context_length,
                                                                const uint8_t* auth_token,
                                                                size_t auth_token_length,
                                                                const uint8_t* encrypted_message,
                                                                size_t encrypted_message_length,
                                                                uint8_t* message,
                                                                size_t* message_length)
{
    ecrypt_status_t res = ECRYPT_FAIL;
    uint32_t expected_message_length = 0;

    ECRYPT_CHECK_PARAM(passphrase != NULL && passphrase_length != 0);
    if (user_context_length != 0) {
        ECRYPT_CHECK_PARAM(user_context != NULL);
    }
    ECRYPT_CHECK_PARAM(auth_token != NULL && auth_token_length != 0);
    ECRYPT_CHECK_PARAM(message_length != NULL);

    /* Do a quick guess without parsing the message too deeply here */
    res = ecrypt_scell_auth_token_message_size(auth_token, auth_token_length, &expected_message_length);
    if (res != ECRYPT_SUCCESS) {
        return res;
    }
    if (!message || *message_length < expected_message_length) {
        *message_length = expected_message_length;
        return ECRYPT_BUFFER_TOO_SMALL;
    }

    /* encrypted_message may be omitted when only querying plaintext size */
    ECRYPT_CHECK_PARAM(encrypted_message != NULL && encrypted_message_length != 0);

    return ecrypt_auth_sym_decrypt_message_with_passphrase_(passphrase,
                                                            passphrase_length,
                                                            user_context,
                                                            user_context_length,
                                                            auth_token,
                                                            auth_token_length,
                                                            encrypted_message,
                                                            encrypted_message_length,
                                                            message,
                                                            message_length);
}
