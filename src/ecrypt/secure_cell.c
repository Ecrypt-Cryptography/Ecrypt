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

#include "ecrypt/secure_cell.h"

#include "ecrypt/secure_cell_seal_passphrase.h"
#include "ecrypt/sym_enc_message.h"

ecrypt_status_t ecrypt_secure_cell_encrypt_seal(const uint8_t* master_key,
                                                const size_t master_key_length,
                                                const uint8_t* user_context,
                                                const size_t user_context_length,
                                                const uint8_t* message,
                                                const size_t message_length,
                                                uint8_t* encrypted_message,
                                                size_t* encrypted_message_length)
{
    size_t ctx_length_;
    size_t msg_length_;
    size_t total_length;

    ECRYPT_CHECK_PARAM(encrypted_message_length != NULL);
    ECRYPT_STATUS_CHECK(ecrypt_auth_sym_encrypt_message(master_key,
                                                        master_key_length,
                                                        message,
                                                        message_length,
                                                        user_context,
                                                        user_context_length,
                                                        NULL,
                                                        &ctx_length_,
                                                        NULL,
                                                        &msg_length_),
                        ECRYPT_BUFFER_TOO_SMALL);

    total_length = ctx_length_ + msg_length_;
    if (!encrypted_message || *encrypted_message_length < total_length) {
        *encrypted_message_length = total_length;
        return ECRYPT_BUFFER_TOO_SMALL;
    }

    *encrypted_message_length = total_length;
    return ecrypt_auth_sym_encrypt_message(master_key,
                                           master_key_length,
                                           message,
                                           message_length,
                                           user_context,
                                           user_context_length,
                                           encrypted_message,
                                           &ctx_length_,
                                           encrypted_message + ctx_length_,
                                           &msg_length_);
}

ecrypt_status_t ecrypt_secure_cell_decrypt_seal(const uint8_t* master_key,
                                                const size_t master_key_length,
                                                const uint8_t* user_context,
                                                const size_t user_context_length,
                                                const uint8_t* encrypted_message,
                                                const size_t encrypted_message_length,
                                                uint8_t* plain_message,
                                                size_t* plain_message_length)
{
    size_t ctx_length_ = 0;
    size_t msg_length_ = 0;
    ECRYPT_STATUS_CHECK(ecrypt_auth_sym_decrypt_message(master_key,
                                                        master_key_length,
                                                        user_context,
                                                        user_context_length,
                                                        encrypted_message,
                                                        encrypted_message_length,
                                                        NULL,
                                                        0,
                                                        NULL,
                                                        &msg_length_),
                        ECRYPT_BUFFER_TOO_SMALL);
    if (encrypted_message_length < msg_length_) {
        return ECRYPT_INVALID_PARAMETER;
    }
    ctx_length_ = encrypted_message_length - msg_length_;
    return ecrypt_auth_sym_decrypt_message(master_key,
                                           master_key_length,
                                           user_context,
                                           user_context_length,
                                           encrypted_message,
                                           ctx_length_,
                                           encrypted_message + ctx_length_,
                                           msg_length_,
                                           plain_message,
                                           plain_message_length);
}

ecrypt_status_t ecrypt_secure_cell_encrypt_seal_with_passphrase(const uint8_t* passphrase,
                                                                size_t passphrase_length,
                                                                const uint8_t* user_context,
                                                                size_t user_context_length,
                                                                const uint8_t* message,
                                                                size_t message_length,
                                                                uint8_t* encrypted_message,
                                                                size_t* encrypted_message_length)
{
    ecrypt_status_t res = ECRYPT_FAIL;
    size_t auth_token_length = 0;
    size_t ciphertext_length = 0;
    size_t total_length = 0;

    ECRYPT_CHECK_PARAM(encrypted_message_length != NULL);

    /*
     * Since Seal mode prepends authentication token to the message
     * we need to get the size of this token at first.
     */
    res = ecrypt_auth_sym_encrypt_message_with_passphrase(passphrase,
                                                          passphrase_length,
                                                          message,
                                                          message_length,
                                                          user_context,
                                                          user_context_length,
                                                          NULL,
                                                          &auth_token_length,
                                                          NULL,
                                                          &ciphertext_length);
    if (res != ECRYPT_BUFFER_TOO_SMALL) {
        return res;
    }

    total_length = auth_token_length + ciphertext_length;
    if (!encrypted_message || *encrypted_message_length < total_length) {
        *encrypted_message_length = total_length;
        return ECRYPT_BUFFER_TOO_SMALL;
    }

    res = ecrypt_auth_sym_encrypt_message_with_passphrase(passphrase,
                                                          passphrase_length,
                                                          message,
                                                          message_length,
                                                          user_context,
                                                          user_context_length,
                                                          encrypted_message,
                                                          &auth_token_length,
                                                          encrypted_message + auth_token_length,
                                                          &ciphertext_length);
    if (res == ECRYPT_SUCCESS || res == ECRYPT_BUFFER_TOO_SMALL) {
        *encrypted_message_length = auth_token_length + ciphertext_length;
    }
    return res;
}

ecrypt_status_t ecrypt_secure_cell_decrypt_seal_with_passphrase(const uint8_t* passphrase,
                                                                size_t passphrase_length,
                                                                const uint8_t* user_context,
                                                                size_t user_context_length,
                                                                const uint8_t* encrypted_message,
                                                                size_t encrypted_message_length,
                                                                uint8_t* plain_message,
                                                                size_t* plain_message_length)
{
    ecrypt_status_t res = ECRYPT_FAIL;
    size_t auth_token_length = 0;
    size_t message_length = 0;

    ECRYPT_CHECK_PARAM(plain_message_length != NULL);

    /*
     * Since Seal mode prepends authentication token to the message we need
     * to get the size of this token at first. Token size is not available
     * directly so we infer it from the size of encrypted message and
     * plaintext message length embedded in the token.
     *
     * Note that this might fail if the encrypted message does not start with
     * a valid token. It also might produce a false positive if the data looks
     * like a token but does not contain valid measurements. This will lead to
     * a decryption failure later.
     */
    res = ecrypt_auth_sym_decrypt_message_with_passphrase(passphrase,
                                                          passphrase_length,
                                                          user_context,
                                                          user_context_length,
                                                          encrypted_message,
                                                          encrypted_message_length,
                                                          NULL,
                                                          0,
                                                          NULL,
                                                          &message_length);
    if (res != ECRYPT_BUFFER_TOO_SMALL) {
        return res;
    }

    /* We should not overflow here. If we do then the message is corrupted. */
    if (encrypted_message_length < message_length) {
        return ECRYPT_FAIL;
    }
    auth_token_length = encrypted_message_length - message_length;

    res = ecrypt_auth_sym_decrypt_message_with_passphrase(passphrase,
                                                          passphrase_length,
                                                          user_context,
                                                          user_context_length,
                                                          encrypted_message,
                                                          auth_token_length,
                                                          encrypted_message + auth_token_length,
                                                          message_length,
                                                          plain_message,
                                                          plain_message_length);
    return res;
}

ecrypt_status_t ecrypt_secure_cell_encrypt_token_protect(const uint8_t* master_key,
                                                         const size_t master_key_length,
                                                         const uint8_t* user_context,
                                                         const size_t user_context_length,
                                                         const uint8_t* message,
                                                         const size_t message_length,
                                                         uint8_t* context,
                                                         size_t* context_length,
                                                         uint8_t* encrypted_message,
                                                         size_t* encrypted_message_length)
{
    return ecrypt_auth_sym_encrypt_message(master_key,
                                           master_key_length,
                                           message,
                                           message_length,
                                           user_context,
                                           user_context_length,
                                           context,
                                           context_length,
                                           encrypted_message,
                                           encrypted_message_length);
}

ecrypt_status_t ecrypt_secure_cell_decrypt_token_protect(const uint8_t* master_key,
                                                         const size_t master_key_length,
                                                         const uint8_t* user_context,
                                                         const size_t user_context_length,
                                                         const uint8_t* encrypted_message,
                                                         const size_t encrypted_message_length,
                                                         const uint8_t* context,
                                                         const size_t context_length,
                                                         uint8_t* plain_message,
                                                         size_t* plain_message_length)
{
    return ecrypt_auth_sym_decrypt_message(master_key,
                                           master_key_length,
                                           user_context,
                                           user_context_length,
                                           context,
                                           context_length,
                                           encrypted_message,
                                           encrypted_message_length,
                                           plain_message,
                                           plain_message_length);
}

ecrypt_status_t ecrypt_secure_cell_encrypt_context_imprint(const uint8_t* master_key,
                                                           const size_t master_key_length,
                                                           const uint8_t* message,
                                                           const size_t message_length,
                                                           const uint8_t* context,
                                                           const size_t context_length,
                                                           uint8_t* encrypted_message,
                                                           size_t* encrypted_message_length)
{
    return ecrypt_sym_encrypt_message_u(master_key,
                                        master_key_length,
                                        context,
                                        context_length,
                                        message,
                                        message_length,
                                        encrypted_message,
                                        encrypted_message_length);
}

ecrypt_status_t ecrypt_secure_cell_decrypt_context_imprint(const uint8_t* master_key,
                                                           const size_t master_key_length,
                                                           const uint8_t* encrypted_message,
                                                           const size_t encrypted_message_length,
                                                           const uint8_t* context,
                                                           const size_t context_length,
                                                           uint8_t* plain_message,
                                                           size_t* plain_message_length)
{
    return ecrypt_sym_decrypt_message_u(master_key,
                                        master_key_length,
                                        context,
                                        context_length,
                                        encrypted_message,
                                        encrypted_message_length,
                                        plain_message,
                                        plain_message_length);
}
