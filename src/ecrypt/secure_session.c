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

#include "ecrypt/secure_session.h"

#include <string.h>

#include "ecconnect/ecconnect_ec_key.h"
#include "ecconnect/ecconnect_rsa_key.h"
#include "ecconnect/ecconnect_t.h"
#include "ecconnect/ecconnect_wipe.h"

#include "ecrypt/secure_keygen.h"
#include "ecrypt/secure_session_t.h"
#include "ecrypt/secure_session_utils.h"
#include "ecrypt/ecrypt_portable_endian.h"

#define SESSION_ID_GENERATION_LABEL "Ecrypt secure session unique identifier"
#define SESSION_MASTER_KEY_GENERATION_LABEL "Ecrypt secure session master key"

static ecrypt_status_t secure_session_accept(secure_session_t* session_ctx,
                                             const void* data,
                                             size_t data_length,
                                             void* output,
                                             size_t* output_length);
static ecrypt_status_t secure_session_proceed_client(secure_session_t* session_ctx,
                                                     const void* data,
                                                     size_t data_length,
                                                     void* output,
                                                     size_t* output_length);
static ecrypt_status_t secure_session_finish_client(secure_session_t* session_ctx,
                                                    const void* data,
                                                    size_t data_length,
                                                    void* output,
                                                    size_t* output_length);
static ecrypt_status_t secure_session_finish_server(secure_session_t* session_ctx,
                                                    const void* data,
                                                    size_t data_length,
                                                    void* output,
                                                    size_t* output_length);

ecrypt_status_t secure_session_cleanup(secure_session_t* session_ctx)
{
    if (NULL == session_ctx) {
        return ECRYPT_INVALID_PARAMETER;
    }

    secure_session_peer_cleanup(&(session_ctx->peer));
    secure_session_peer_cleanup(&(session_ctx->we));

    ecconnect_asym_ka_cleanup(&(session_ctx->ecdh_ctx));

    ecconnect_wipe(session_ctx, sizeof(secure_session_t));

    return ECRYPT_SUCCESS;
}

ecrypt_status_t secure_session_destroy(secure_session_t* session_ctx)
{
    ecrypt_status_t res = secure_session_cleanup(session_ctx);

    if (ECRYPT_SUCCESS == res) {
        free(session_ctx);
    }

    return res;
}

static ecrypt_status_t secure_session_check_user_callbacks(const secure_session_user_callbacks_t* user_callbacks)
{
    if (!user_callbacks) {
        return ECRYPT_INVALID_PARAMETER;
    }

    if (!user_callbacks->get_public_key_for_id) {
        return ECRYPT_INVALID_PARAMETER;
    }

    return ECRYPT_SUCCESS;
}

ecrypt_status_t secure_session_init(secure_session_t* session_ctx,
                                    const void* id,
                                    size_t id_length,
                                    const void* sign_key,
                                    size_t sign_key_length,
                                    const secure_session_user_callbacks_t* user_callbacks)
{
    ecconnect_status_t ecconnect_status;
    ecrypt_status_t res = ECRYPT_SUCCESS;

    /* This change prevents from using RSA keys in Secure Session,
     * as they are currently not supported */
    ecrypt_key_kind_t key_kind = ecrypt_get_asym_key_kind(sign_key, sign_key_length);
    if (key_kind != ECRYPT_KEY_EC_PRIVATE) {
        res = ECRYPT_INVALID_PARAMETER;
        goto err;
    }

    res = secure_session_check_user_callbacks(user_callbacks);
    if (ECRYPT_SUCCESS != res) {
        goto err;
    }

    res = secure_session_peer_init(&(session_ctx->we), id, id_length, NULL, 0, sign_key, sign_key_length);
    if (ECRYPT_SUCCESS != res) {
        goto err;
    }

    session_ctx->user_callbacks = user_callbacks;

    ecconnect_status = ecconnect_asym_ka_init(&(session_ctx->ecdh_ctx), ECCONNECT_ASYM_KA_EC_P256);
    if (ECRYPT_SUCCESS != ecconnect_status) {
        res = ecconnect_status;
        goto err;
    }

    ecconnect_status = ecconnect_asym_ka_gen_key(&(session_ctx->ecdh_ctx));
    if (ECRYPT_SUCCESS != ecconnect_status) {
        res = ecconnect_status;
        goto err;
    }

    /* Initially we are in the "server accept" mode */
    session_ctx->state_handler = secure_session_accept;

err:

    if (ECRYPT_SUCCESS != res) {
        secure_session_cleanup(session_ctx);
    }
    return res;
}

secure_session_t* secure_session_create(const void* id,
                                        size_t id_length,
                                        const void* sign_key,
                                        size_t sign_key_length,
                                        const secure_session_user_callbacks_t* user_callbacks)
{
    secure_session_t* ctx = calloc(sizeof(secure_session_t), 1);

    if (!ctx) {
        return NULL;
    }

    memset(ctx, 0, sizeof(secure_session_t));

    if (ECRYPT_SUCCESS
        == secure_session_init(ctx, id, id_length, sign_key, sign_key_length, user_callbacks)) {
        return ctx;
    }

    free(ctx);
    return NULL;
}

ecrypt_status_t secure_session_generate_connect_request(secure_session_t* session_ctx,
                                                        void* output,
                                                        size_t* output_length)
{
    uint8_t* data_to_send = output;
    size_t length_to_send;

    ecconnect_container_hdr_t* container;

    size_t ecdh_key_length = 0;
    size_t signature_length = 0;

    ecconnect_status_t ecconnect_status;
    ecrypt_status_t res = ECRYPT_SUCCESS;

    ecconnect_kdf_context_buf_t sign_data;

    ecconnect_status = ecconnect_asym_ka_export_key(&(session_ctx->ecdh_ctx), NULL, &ecdh_key_length, false);
    if (ECRYPT_BUFFER_TOO_SMALL != ecconnect_status) {
        return ecconnect_status;
    }
    res = compute_signature(session_ctx->we.sign_key,
                            session_ctx->we.sign_key_length,
                            NULL,
                            0,
                            NULL,
                            &signature_length);
    if (ECRYPT_BUFFER_TOO_SMALL != res) {
        return res;
    }
    length_to_send = 2 * sizeof(ecconnect_container_hdr_t) + session_ctx->we.id_length + ecdh_key_length
                     + signature_length;
    if ((NULL == output) || (*output_length < length_to_send)) {
        *output_length = length_to_send;
        return ECRYPT_BUFFER_TOO_SMALL;
    }

    /* Storing ID in a container */
    container = ((ecconnect_container_hdr_t*)data_to_send) + 1;

    memcpy(container->tag, ECRYPT_SESSION_ID_TAG, ECCONNECT_CONTAINER_TAG_LENGTH);
    ecconnect_container_set_data_size(container, session_ctx->we.id_length);
    memcpy(ecconnect_container_data(container), session_ctx->we.id, session_ctx->we.id_length);
    ecconnect_update_container_checksum(container);

    /* Moving back to beginning of allocated buffer */
    container = (ecconnect_container_hdr_t*)data_to_send;

    ecconnect_status = ecconnect_asym_ka_export_key(&(session_ctx->ecdh_ctx),
                                            data_to_send + (2 * sizeof(ecconnect_container_hdr_t))
                                                + session_ctx->we.id_length,
                                            &ecdh_key_length,
                                            false);
    if (ECRYPT_SUCCESS != ecconnect_status) {
        return ecconnect_status;
    }
    sign_data.data = data_to_send + (2 * sizeof(ecconnect_container_hdr_t)) + session_ctx->we.id_length;
    sign_data.length = ecdh_key_length;

    /* Actual signature may be 1 or 2 bytes less than reported above because leading zeroes are
     * stripped */
    length_to_send -= signature_length;

    res = compute_signature(session_ctx->we.sign_key,
                            session_ctx->we.sign_key_length,
                            &sign_data,
                            1,
                            data_to_send + (2 * sizeof(ecconnect_container_hdr_t))
                                + session_ctx->we.id_length + ecdh_key_length,
                            &signature_length);
    if (ECRYPT_SUCCESS != res) {
        return res;
    }

    length_to_send += signature_length;
    *output_length = length_to_send;

    memcpy(container->tag, ECRYPT_SESSION_PROTO_TAG, ECCONNECT_CONTAINER_TAG_LENGTH);
    ecconnect_container_set_data_size(container, length_to_send - sizeof(ecconnect_container_hdr_t));
    ecconnect_update_container_checksum(container);

    /* In "client mode" awaiting initial response from the server */
    session_ctx->state_handler = secure_session_proceed_client;
    session_ctx->is_client = true;

    if (session_ctx->user_callbacks->state_changed) {
        session_ctx->user_callbacks->state_changed(STATE_NEGOTIATING,
                                                   session_ctx->user_callbacks->user_data);
    }

    return ECRYPT_SUCCESS;
}

ecrypt_status_t secure_session_connect(secure_session_t* session_ctx)
{
    uint8_t stack_buf[2048];

    size_t request_length = sizeof(stack_buf);
    uint8_t* request = stack_buf;

    ecrypt_status_t res = secure_session_generate_connect_request(session_ctx, request, &request_length);

    if (ECRYPT_BUFFER_TOO_SMALL == res) {
        request = malloc(request_length);
        if (!request) {
            return ECRYPT_NO_MEMORY;
        }

        res = secure_session_generate_connect_request(session_ctx, request, &request_length);
    }

    if (ECRYPT_SUCCESS == res) {
        ssize_t bytes_sent = -1;

        if (session_ctx->user_callbacks->send_data) {
            bytes_sent = session_ctx->user_callbacks->send_data(request,
                                                                request_length,
                                                                session_ctx->user_callbacks->user_data);
        }

        if (bytes_sent != (ssize_t)request_length) {
            res = ECRYPT_SSESSION_TRANSPORT_ERROR;

            /* revert the state back */
            session_ctx->state_handler = secure_session_accept;
            session_ctx->is_client = false;
        }
    }

    if (request != stack_buf) {
        free(request);
    }

    return res;
}

static ecrypt_status_t secure_session_accept(secure_session_t* session_ctx,
                                             const void* data,
                                             size_t data_length,
                                             void* output,
                                             size_t* output_length)
{
    const ecconnect_container_hdr_t* proto_message = data;
    const ecconnect_container_hdr_t* peer_id;

    const ecconnect_container_hdr_t* peer_ecdh_key;
    size_t peer_ecdh_key_length;

    const uint8_t* signature;
    size_t signature_length;

    ecrypt_status_t res = ECRYPT_SUCCESS;
    ecconnect_status_t ecconnect_status;

    uint8_t sign_key[1024]; /* Should be enough for RSA 8192 which is 512 bytes */
    size_t sign_key_length;

    const ecconnect_container_hdr_t* peer_sign_key;
    ecconnect_kdf_context_buf_t sign_data[4];

    uint8_t* data_to_send = output;
    size_t length_to_send;

    size_t ecdh_key_length = 0;
    ecconnect_container_hdr_t* container;

    if (data_length < sizeof(ecconnect_container_hdr_t)) {
        return ECRYPT_INVALID_PARAMETER;
    }

    if (memcmp(proto_message->tag, ECRYPT_SESSION_PROTO_TAG, ECCONNECT_CONTAINER_TAG_LENGTH) != 0) {
        return ECRYPT_INVALID_PARAMETER;
    }

    if (data_length < (ecconnect_container_data_size(proto_message) + sizeof(ecconnect_container_hdr_t))) {
        return ECRYPT_INVALID_PARAMETER;
    }

    if (ECRYPT_SUCCESS != ecconnect_verify_container_checksum(proto_message)) {

        return ECRYPT_INVALID_PARAMETER;
    }

    peer_id = (const ecconnect_container_hdr_t*)ecconnect_container_const_data(proto_message);

    if (memcmp(peer_id->tag, ECRYPT_SESSION_ID_TAG, ECCONNECT_CONTAINER_TAG_LENGTH) != 0) {
        return ECRYPT_INVALID_PARAMETER;
    }

    if (ECRYPT_SUCCESS != ecconnect_verify_container_checksum(peer_id)) {
        return ECRYPT_INVALID_PARAMETER;
    }

    peer_ecdh_key = (const ecconnect_container_hdr_t*)(ecconnect_container_const_data(peer_id)
                                                   + ecconnect_container_data_size(peer_id));

    if (memcmp(peer_ecdh_key->tag, EC_PUB_KEY_PREF, strlen(EC_PUB_KEY_PREF)) != 0) {
        return ECRYPT_INVALID_PARAMETER;
    }

    peer_ecdh_key_length = ecconnect_container_data_size(peer_ecdh_key) + sizeof(ecconnect_container_hdr_t);

    signature = (const uint8_t*)peer_ecdh_key + peer_ecdh_key_length;
    signature_length = (const uint8_t*)data + ecconnect_container_data_size(proto_message)
                       + sizeof(ecconnect_container_hdr_t) - signature;
    if (session_ctx->user_callbacks->get_public_key_for_id(ecconnect_container_const_data(peer_id),
                                                           ecconnect_container_data_size(peer_id),
                                                           sign_key,
                                                           sizeof(sign_key),
                                                           session_ctx->user_callbacks->user_data)) {
        return ECRYPT_SSESSION_GET_PUB_FOR_ID_CALLBACK_ERROR;
    }

    peer_sign_key = (const ecconnect_container_hdr_t*)sign_key;

    if (memcmp(peer_sign_key->tag, EC_PUB_KEY_PREF, strlen(EC_PUB_KEY_PREF)) != 0) {
        return ECRYPT_INVALID_PARAMETER;
    }

    sign_key_length = be32toh(peer_sign_key->size);

    if (sizeof(ecconnect_container_hdr_t) >= sign_key_length) {
        return ECRYPT_INVALID_PARAMETER;
    }

    sign_data[0].data = (const uint8_t*)peer_ecdh_key;
    sign_data[0].length = peer_ecdh_key_length;

    res = verify_signature(peer_sign_key, sign_key_length, sign_data, 1, signature, signature_length);
    if (ECRYPT_SUCCESS != res) {
        return res;
    }

    /* Preparing to send response */
    res = compute_signature(session_ctx->we.sign_key,
                            session_ctx->we.sign_key_length,
                            NULL,
                            0,
                            NULL,
                            &signature_length);
    if (ECRYPT_BUFFER_TOO_SMALL != res) {
        return res;
    }

    ecconnect_status = ecconnect_asym_ka_export_key(&(session_ctx->ecdh_ctx), NULL, &ecdh_key_length, false);
    if (ECRYPT_BUFFER_TOO_SMALL != ecconnect_status) {
        return ecconnect_status;
    }

    length_to_send = 2 * sizeof(ecconnect_container_hdr_t) + session_ctx->we.id_length + ecdh_key_length
                     + signature_length;
    if ((NULL == output) || (*output_length < length_to_send)) {
        *output_length = length_to_send;
        return ECRYPT_BUFFER_TOO_SMALL;
    }

    res = secure_session_peer_init(&(session_ctx->peer),
                                   ecconnect_container_const_data(peer_id),
                                   ecconnect_container_data_size(peer_id),
                                   peer_ecdh_key,
                                   peer_ecdh_key_length,
                                   peer_sign_key,
                                   sign_key_length);
    if (ECRYPT_SUCCESS != res) {
        goto err;
    }

    /* Storing ID in a container */
    container = (ecconnect_container_hdr_t*)data_to_send + 1;

    memcpy(container->tag, ECRYPT_SESSION_ID_TAG, ECCONNECT_CONTAINER_TAG_LENGTH);
    ecconnect_container_set_data_size(container, session_ctx->we.id_length);
    memcpy(ecconnect_container_data(container), session_ctx->we.id, session_ctx->we.id_length);
    ecconnect_update_container_checksum(container);

    /* Moving back to beginning of allocated buffer */
    container = (ecconnect_container_hdr_t*)data_to_send;

    ecconnect_status = ecconnect_asym_ka_export_key(&(session_ctx->ecdh_ctx),
                                            data_to_send + (2 * sizeof(ecconnect_container_hdr_t))
                                                + session_ctx->we.id_length,
                                            &ecdh_key_length,
                                            false);
    if (ECRYPT_SUCCESS != ecconnect_status) {
        res = ecconnect_status;
        goto err;
    }

    sign_data[0].data = data_to_send + (2 * sizeof(ecconnect_container_hdr_t)) + session_ctx->we.id_length;
    sign_data[0].length = ecdh_key_length;

    sign_data[1].data = session_ctx->peer.ecdh_key;
    sign_data[1].length = session_ctx->peer.ecdh_key_length;

    sign_data[2].data = session_ctx->we.id;
    sign_data[2].length = session_ctx->we.id_length;

    sign_data[3].data = session_ctx->peer.id;
    sign_data[3].length = session_ctx->peer.id_length;

    /* Actual signature may be 1 or 2 bytes less than reported above because leading zeroes are
     * stripped */
    length_to_send -= signature_length;

    res = compute_signature(session_ctx->we.sign_key,
                            session_ctx->we.sign_key_length,
                            sign_data,
                            4,
                            data_to_send + (2 * sizeof(ecconnect_container_hdr_t))
                                + session_ctx->we.id_length + ecdh_key_length,
                            &signature_length);
    if (ECRYPT_SUCCESS != res) {
        goto err;
    }

    length_to_send += signature_length;
    *output_length = length_to_send;

    memcpy(container->tag, ECRYPT_SESSION_PROTO_TAG, ECCONNECT_CONTAINER_TAG_LENGTH);
    ecconnect_container_set_data_size(container, length_to_send - sizeof(ecconnect_container_hdr_t));
    ecconnect_update_container_checksum(container);

    /* "Server mode": waiting response from the client */
    session_ctx->state_handler = secure_session_finish_server;

    if (session_ctx->user_callbacks->state_changed) {
        session_ctx->user_callbacks->state_changed(STATE_NEGOTIATING,
                                                   session_ctx->user_callbacks->user_data);
    }

err:

    if (ECRYPT_SUCCESS != res) {
        secure_session_peer_cleanup(&(session_ctx->peer));
    }

    return res;
}

static ecrypt_status_t secure_session_proceed_client(secure_session_t* session_ctx,
                                                     const void* data,
                                                     size_t data_length,
                                                     void* output,
                                                     size_t* output_length)
{
    const ecconnect_container_hdr_t* proto_message = data;
    const ecconnect_container_hdr_t* peer_id;

    const ecconnect_container_hdr_t* peer_ecdh_key;
    size_t peer_ecdh_key_length;

    const uint8_t* signature;
    size_t signature_length;

    ecrypt_status_t res = ECRYPT_SUCCESS;
    ecconnect_status_t ecconnect_status;

    uint8_t sign_key[1024]; /* Should be enough for RSA 8192 which is 512 bytes */
    size_t sign_key_length;

    uint8_t ecdh_key[1024];
    size_t ecdh_key_length = sizeof(ecdh_key);

    const ecconnect_container_hdr_t* peer_sign_key;
    ecconnect_kdf_context_buf_t sign_data[4];

    uint8_t* data_to_send = output;
    size_t length_to_send;

    ecconnect_container_hdr_t* container;
    uint8_t* mac;

    if (data_length < sizeof(ecconnect_container_hdr_t)) {
        return ECRYPT_INVALID_PARAMETER;
    }

    if (memcmp(proto_message->tag, ECRYPT_SESSION_PROTO_TAG, ECCONNECT_CONTAINER_TAG_LENGTH) != 0) {
        return ECRYPT_INVALID_PARAMETER;
    }

    if (data_length < (ecconnect_container_data_size(proto_message) + sizeof(ecconnect_container_hdr_t))) {
        return ECRYPT_INVALID_PARAMETER;
    }

    if (ECRYPT_SUCCESS != ecconnect_verify_container_checksum(proto_message)) {
        return ECRYPT_INVALID_PARAMETER;
    }

    peer_id = (const ecconnect_container_hdr_t*)ecconnect_container_const_data(proto_message);

    if (memcmp(peer_id->tag, ECRYPT_SESSION_ID_TAG, ECCONNECT_CONTAINER_TAG_LENGTH) != 0) {
        return ECRYPT_INVALID_PARAMETER;
    }

    if (ECRYPT_SUCCESS != ecconnect_verify_container_checksum(peer_id)) {
        return ECRYPT_INVALID_PARAMETER;
    }

    peer_ecdh_key = (const ecconnect_container_hdr_t*)(ecconnect_container_const_data(peer_id)
                                                   + ecconnect_container_data_size(peer_id));

    if (memcmp(peer_ecdh_key->tag, EC_PUB_KEY_PREF, strlen(EC_PUB_KEY_PREF)) != 0) {
        return ECRYPT_INVALID_PARAMETER;
    }

    peer_ecdh_key_length = be32toh(peer_ecdh_key->size);

    signature = (const uint8_t*)peer_ecdh_key + peer_ecdh_key_length;
    signature_length = (const uint8_t*)data + ecconnect_container_data_size(proto_message)
                       + sizeof(ecconnect_container_hdr_t) - signature;
    if (session_ctx->user_callbacks->get_public_key_for_id(ecconnect_container_const_data(peer_id),
                                                           ecconnect_container_data_size(peer_id),
                                                           sign_key,
                                                           sizeof(sign_key),
                                                           session_ctx->user_callbacks->user_data)) {
        return ECRYPT_SSESSION_GET_PUB_FOR_ID_CALLBACK_ERROR;
    }

    peer_sign_key = (const ecconnect_container_hdr_t*)sign_key;

    if (memcmp(peer_sign_key->tag, EC_PUB_KEY_PREF, strlen(EC_PUB_KEY_PREF)) != 0) {
        return ECRYPT_INVALID_PARAMETER;
    }

    sign_key_length = be32toh(peer_sign_key->size);

    if (sizeof(ecconnect_container_hdr_t) >= sign_key_length) {
        return ECRYPT_INVALID_PARAMETER;
    }

    ecconnect_status = ecconnect_asym_ka_export_key(&(session_ctx->ecdh_ctx), ecdh_key, &ecdh_key_length, false);
    if (ECRYPT_SUCCESS != ecconnect_status) {
        return ecconnect_status;
    }

    sign_data[0].data = (const uint8_t*)peer_ecdh_key;
    sign_data[0].length = peer_ecdh_key_length;

    sign_data[1].data = ecdh_key;
    sign_data[1].length = ecdh_key_length;

    sign_data[2].data = ecconnect_container_const_data(peer_id);
    sign_data[2].length = ecconnect_container_data_size(peer_id);

    sign_data[3].data = session_ctx->we.id;
    sign_data[3].length = session_ctx->we.id_length;

    res = verify_signature(peer_sign_key, sign_key_length, sign_data, 4, signature, signature_length);
    if (ECRYPT_SUCCESS != res) {
        return res;
    }

    res = secure_session_peer_init(&(session_ctx->peer),
                                   ecconnect_container_const_data(peer_id),
                                   ecconnect_container_data_size(peer_id),
                                   peer_ecdh_key,
                                   peer_ecdh_key_length,
                                   peer_sign_key,
                                   sign_key_length);
    if (ECRYPT_SUCCESS != res) {
        goto err;
    }

    sign_data[0].data = ecdh_key;
    sign_data[0].length = ecdh_key_length;

    sign_data[1].data = (const uint8_t*)peer_ecdh_key;
    sign_data[1].length = peer_ecdh_key_length;

    sign_data[2].data = session_ctx->we.id;
    sign_data[2].length = session_ctx->we.id_length;

    sign_data[3].data = ecconnect_container_const_data(peer_id);
    sign_data[3].length = ecconnect_container_data_size(peer_id);

    res = ecconnect_kdf(NULL,
                    0,
                    SESSION_ID_GENERATION_LABEL,
                    sign_data,
                    4,
                    &(session_ctx->session_id),
                    sizeof(session_ctx->session_id));
    if (ECRYPT_SUCCESS != res) {
        goto err;
    }

    /* we will reuse sign_key buffer for shared secret computation */
    sign_key_length = sizeof(sign_key);
    res = ecconnect_asym_ka_derive(&(session_ctx->ecdh_ctx),
                               peer_ecdh_key,
                               peer_ecdh_key_length,
                               sign_key,
                               &sign_key_length);
    if (ECRYPT_SUCCESS != res) {
        goto err;
    }

    sign_data[0].data = (const uint8_t*)(&(session_ctx->session_id));
    sign_data[0].length = sizeof(session_ctx->session_id);

    res = ecconnect_kdf(sign_key,
                    sign_key_length,
                    SESSION_MASTER_KEY_GENERATION_LABEL,
                    sign_data,
                    1,
                    session_ctx->session_master_key,
                    sizeof(session_ctx->session_master_key));
    if (ECRYPT_SUCCESS != res) {
        goto err;
    }

    /* restore sign data for signature computation */
    sign_data[0].data = ecdh_key;
    sign_data[0].length = ecdh_key_length;

    res = compute_signature(session_ctx->we.sign_key,
                            session_ctx->we.sign_key_length,
                            NULL,
                            0,
                            NULL,
                            &signature_length);
    if (ECRYPT_BUFFER_TOO_SMALL != res) {
        goto err;
    }

    /* we will reuse sign_key_length for mac length retrieval */
    res = compute_mac(session_ctx->session_master_key,
                      sizeof(session_ctx->session_master_key),
                      NULL,
                      0,
                      NULL,
                      &sign_key_length);
    if (ECRYPT_BUFFER_TOO_SMALL != res) {
        goto err;
    }

    length_to_send = sizeof(ecconnect_container_hdr_t) + signature_length + sign_key_length;
    if ((NULL == output) || (*output_length < length_to_send)) {
        *output_length = length_to_send;
        res = ECRYPT_BUFFER_TOO_SMALL;
        goto err;
    }

    container = (ecconnect_container_hdr_t*)data_to_send;

    /* Actual signature may be 1 or 2 bytes less than reported above because leading zeroes are
     * stripped */
    length_to_send -= signature_length;

    res = compute_signature(session_ctx->we.sign_key,
                            session_ctx->we.sign_key_length,
                            sign_data,
                            4,
                            ecconnect_container_data(container),
                            &signature_length);
    if (ECRYPT_SUCCESS != res) {
        goto err;
    }

    length_to_send += signature_length;
    mac = ecconnect_container_data(container) + signature_length;

    sign_data[0].data = (const uint8_t*)(session_ctx->peer.ecdh_key);
    sign_data[0].length = session_ctx->peer.ecdh_key_length;

    sign_data[1].data = (const uint8_t*)(&(session_ctx->session_id));
    sign_data[1].length = sizeof(session_ctx->session_id);

    res = compute_mac(session_ctx->session_master_key,
                      sizeof(session_ctx->session_master_key),
                      sign_data,
                      2,
                      mac,
                      &sign_key_length);
    if (ECRYPT_SUCCESS != res) {
        goto err;
    }

    *output_length = length_to_send;

    memcpy(container->tag, ECRYPT_SESSION_PROTO_TAG, ECCONNECT_CONTAINER_TAG_LENGTH);
    ecconnect_container_set_data_size(container, length_to_send - sizeof(ecconnect_container_hdr_t));
    ecconnect_update_container_checksum(container);

    /* "Client mode": waiting final confirmation from server */
    session_ctx->state_handler = secure_session_finish_client;

err:

    if (ECRYPT_SUCCESS != res) {
        secure_session_peer_cleanup(&(session_ctx->peer));
    }

    return res;
}

static ecrypt_status_t secure_session_finish_server(secure_session_t* session_ctx,
                                                    const void* data,
                                                    size_t data_length,
                                                    void* output,
                                                    size_t* output_length)
{
    const ecconnect_container_hdr_t* proto_message = data;
    ecconnect_container_hdr_t* response_message;
    ecrypt_status_t res;

    const uint8_t* mac;
    size_t mac_length = 0;

    const uint8_t* signature;
    size_t signature_length;

    ecconnect_kdf_context_buf_t sign_data[4];

    uint8_t ecdh_key[1024];
    size_t ecdh_key_length = sizeof(ecdh_key);

    uint8_t shared_secret[1024];
    size_t shared_secret_length = sizeof(shared_secret);

    if (data_length < sizeof(ecconnect_container_hdr_t)) {
        return ECRYPT_INVALID_PARAMETER;
    }

    if (memcmp(proto_message->tag, ECRYPT_SESSION_PROTO_TAG, ECCONNECT_CONTAINER_TAG_LENGTH) != 0) {
        return ECRYPT_INVALID_PARAMETER;
    }

    if (data_length < (ecconnect_container_data_size(proto_message) + sizeof(ecconnect_container_hdr_t))) {
        return ECRYPT_INVALID_PARAMETER;
    }

    if (ECRYPT_SUCCESS != ecconnect_verify_container_checksum(proto_message)) {
        return ECRYPT_INVALID_PARAMETER;
    }

    /* Get length of used mac */
    res = compute_mac(session_ctx->peer.ecdh_key, session_ctx->peer.ecdh_key_length, NULL, 0, NULL, &mac_length);
    if (ECRYPT_BUFFER_TOO_SMALL != res) {
        return res;
    }

    signature_length = ecconnect_container_data_size(proto_message) - mac_length;
    signature = ecconnect_container_const_data(proto_message);
    mac = signature + signature_length;

    res = ecconnect_asym_ka_export_key(&(session_ctx->ecdh_ctx), ecdh_key, &ecdh_key_length, false);
    if (ECRYPT_SUCCESS != res) {
        return res;
    }

    sign_data[0].data = session_ctx->peer.ecdh_key;
    sign_data[0].length = session_ctx->peer.ecdh_key_length;

    sign_data[1].data = ecdh_key;
    sign_data[1].length = ecdh_key_length;

    sign_data[2].data = session_ctx->peer.id;
    sign_data[2].length = session_ctx->peer.id_length;

    sign_data[3].data = session_ctx->we.id;
    sign_data[3].length = session_ctx->we.id_length;

    res = verify_signature(session_ctx->peer.sign_key,
                           session_ctx->peer.sign_key_length,
                           sign_data,
                           4,
                           signature,
                           signature_length);
    if (ECRYPT_SUCCESS != res) {
        return res;
    }

    res = ecconnect_asym_ka_derive(&(session_ctx->ecdh_ctx),
                               session_ctx->peer.ecdh_key,
                               session_ctx->peer.ecdh_key_length,
                               shared_secret,
                               &shared_secret_length);
    if (ECRYPT_SUCCESS != res) {
        return res;
    }

    res = ecconnect_kdf(NULL,
                    0,
                    SESSION_ID_GENERATION_LABEL,
                    sign_data,
                    4,
                    &(session_ctx->session_id),
                    sizeof(session_ctx->session_id));
    if (ECRYPT_SUCCESS != res) {
        return res;
    }

    sign_data[0].data = (const uint8_t*)(&(session_ctx->session_id));
    sign_data[0].length = sizeof(session_ctx->session_id);

    res = ecconnect_kdf(shared_secret,
                    shared_secret_length,
                    SESSION_MASTER_KEY_GENERATION_LABEL,
                    sign_data,
                    1,
                    session_ctx->session_master_key,
                    sizeof(session_ctx->session_master_key));
    if (ECRYPT_SUCCESS != res) {
        return res;
    }

    sign_data[0].data = ecdh_key;
    sign_data[0].length = ecdh_key_length;

    sign_data[1].data = (const uint8_t*)(&(session_ctx->session_id));
    sign_data[1].length = sizeof(session_ctx->session_id);

    res = verify_mac(session_ctx->session_master_key,
                     sizeof(session_ctx->session_master_key),
                     sign_data,
                     2,
                     mac,
                     mac_length);
    if (ECRYPT_SUCCESS != res) {
        return res;
    }

    sign_data[0].data = session_ctx->peer.ecdh_key;
    sign_data[0].length = session_ctx->peer.ecdh_key_length;

    /* we will reuse ecdh_key buffer for mac response computation */
    ecdh_key_length = sizeof(ecdh_key) - sizeof(ecconnect_container_hdr_t);
    response_message = (ecconnect_container_hdr_t*)ecdh_key;

    res = compute_mac(session_ctx->session_master_key,
                      sizeof(session_ctx->session_master_key),
                      sign_data,
                      2,
                      ecconnect_container_data(response_message),
                      &ecdh_key_length);
    if (ECRYPT_SUCCESS != res) {
        return res;
    }

    if ((NULL == output) || (*output_length < (ecdh_key_length + sizeof(ecconnect_container_hdr_t)))) {
        *output_length = ecdh_key_length + sizeof(ecconnect_container_hdr_t);
        return ECRYPT_BUFFER_TOO_SMALL;
    }

    *output_length = ecdh_key_length + sizeof(ecconnect_container_hdr_t);

    res = secure_session_derive_message_keys(session_ctx);
    if (ECRYPT_SUCCESS != res) {
        return res;
    }

    memcpy(response_message->tag, ECRYPT_SESSION_PROTO_TAG, ECCONNECT_CONTAINER_TAG_LENGTH);
    ecconnect_container_set_data_size(response_message, ecdh_key_length);
    ecconnect_update_container_checksum(response_message);

    memcpy(output, ecdh_key, ecconnect_container_data_size(response_message) + sizeof(ecconnect_container_hdr_t));

    /* "Server mode": negotiation completed */
    session_ctx->state_handler = NULL;

    if (session_ctx->user_callbacks->state_changed) {
        session_ctx->user_callbacks->state_changed(STATE_ESTABLISHED,
                                                   session_ctx->user_callbacks->user_data);
    }

    return res;
}

static ecrypt_status_t secure_session_finish_client(secure_session_t* session_ctx,
                                                    const void* data,
                                                    size_t data_length,
                                                    void* output,
                                                    size_t* output_length)
{
    UNUSED(output);
    const ecconnect_container_hdr_t* proto_message = data;
    ecrypt_status_t res;

    uint8_t ecdh_key[1024];
    size_t ecdh_key_length = sizeof(ecdh_key);

    ecconnect_kdf_context_buf_t sign_data[2];

    if (data_length < sizeof(ecconnect_container_hdr_t)) {
        return ECRYPT_INVALID_PARAMETER;
    }

    if (memcmp(proto_message->tag, ECRYPT_SESSION_PROTO_TAG, ECCONNECT_CONTAINER_TAG_LENGTH) != 0) {
        return ECRYPT_INVALID_PARAMETER;
    }

    if (data_length < (ecconnect_container_data_size(proto_message) + sizeof(ecconnect_container_hdr_t))) {
        return ECRYPT_INVALID_PARAMETER;
    }

    if (ECRYPT_SUCCESS != ecconnect_verify_container_checksum(proto_message)) {
        return ECRYPT_INVALID_PARAMETER;
    }

    res = ecconnect_asym_ka_export_key(&(session_ctx->ecdh_ctx), ecdh_key, &ecdh_key_length, false);
    if (ECRYPT_SUCCESS != res) {
        return res;
    }

    sign_data[0].data = ecdh_key;
    sign_data[0].length = ecdh_key_length;

    sign_data[1].data = (const uint8_t*)(&(session_ctx->session_id));
    sign_data[1].length = sizeof(session_ctx->session_id);

    res = verify_mac(session_ctx->session_master_key,
                     sizeof(session_ctx->session_master_key),
                     sign_data,
                     2,
                     ecconnect_container_const_data(proto_message),
                     ecconnect_container_data_size(proto_message));
    if (ECRYPT_SUCCESS != res) {
        return res;
    }

    res = secure_session_derive_message_keys(session_ctx);
    if (ECRYPT_SUCCESS != res) {
        return res;
    }

    *output_length = 0;

    /* "Client mode": negotiation completed */
    session_ctx->state_handler = NULL;

    if (session_ctx->user_callbacks->state_changed) {
        session_ctx->user_callbacks->state_changed(STATE_ESTABLISHED,
                                                   session_ctx->user_callbacks->user_data);
    }

    return res;
}

ssize_t secure_session_send(secure_session_t* session_ctx, const void* message, size_t message_length)
{
    uint8_t stack_buf[2048];

    uint8_t* out;
    size_t out_size = sizeof(stack_buf);

    ecrypt_status_t res;

    ssize_t bytes_sent;

    if ((!session_ctx) || (!message) || (!message_length)) {
        return ECRYPT_INVALID_PARAMETER;
    }

    if (!secure_session_is_established(session_ctx)) {
        /* The key agreement is not finished yet, cannot send any message */
        return ECRYPT_SSESSION_KA_NOT_FINISHED;
    }

    out_size = WRAPPED_SIZE(message_length);

    if (out_size <= sizeof(stack_buf)) {
        /* We may use stack buffer */
        out = stack_buf;
    } else {
        out = malloc(out_size);
        if (!out) {
            return ECRYPT_NO_MEMORY;
        }
    }

    res = secure_session_wrap(session_ctx, message, message_length, out, &out_size);
    if (ECRYPT_SUCCESS != res) {
        message_length = (ssize_t)res;
        goto err;
    }

    if (session_ctx->user_callbacks->send_data) {
        bytes_sent = session_ctx->user_callbacks->send_data(out,
                                                            out_size,
                                                            session_ctx->user_callbacks->user_data);
    } else {
        bytes_sent = -1;
    }

    if (bytes_sent < 0 || (size_t)bytes_sent != out_size) {
        message_length = (ssize_t)ECRYPT_SSESSION_TRANSPORT_ERROR;
    }

err:

    if (out != stack_buf) {
        free(out);
    }

    return message_length;
}

ssize_t secure_session_receive(secure_session_t* session_ctx, void* message, size_t message_length)
{
    uint8_t stack_buf[2048];
    uint8_t* in;
    size_t in_size = sizeof(stack_buf);
    size_t bytes_received;
    ssize_t res;

    if (!session_ctx) {
        return ECRYPT_INVALID_PARAMETER;
    }

    if (secure_session_is_established(session_ctx)) {
        if (!message || !message_length) {
            return ECRYPT_INVALID_PARAMETER;
        }
    }

    if (!secure_session_is_established(session_ctx)) {
        /* We are in key agreement stage. We may always use stack buffer here */
        in = stack_buf;
    } else {
        /* If user is expecting to receive message_length, then we need a buffer to receive at least
         * WRAPPED_SIZE(message_length) */
        in_size = WRAPPED_SIZE(message_length);
        if (in_size < sizeof(stack_buf)) {
            in = stack_buf;
        } else {
            in = malloc(in_size);
            if (!in) {
                return ECRYPT_NO_MEMORY;
            }
        }
    }

    if (session_ctx->user_callbacks->receive_data) {
        res = session_ctx->user_callbacks->receive_data(in, in_size, session_ctx->user_callbacks->user_data);
    } else {
        res = -1;
    }

    if (res < 0) {
        goto err;
    }
    bytes_received = (size_t)res;

    if (!secure_session_is_established(session_ctx)) {
        /*TODO: Needs refactoring */
        uint8_t ka_buf[2048];
        size_t ka_buf_length = sizeof(ka_buf);

        /* save current session state */
        secure_session_handler state = session_ctx->state_handler;

        res = session_ctx->state_handler(session_ctx, stack_buf, bytes_received, ka_buf, &ka_buf_length);
        if ((ECRYPT_SUCCESS == res) && (ka_buf_length > 0)) {
            ssize_t bytes_sent = -1;

            if (session_ctx->user_callbacks->send_data) {
                bytes_sent = session_ctx->user_callbacks->send_data(ka_buf,
                                                                    ka_buf_length,
                                                                    session_ctx->user_callbacks->user_data);
            }

            if (bytes_sent != (ssize_t)ka_buf_length) {
                res = ECRYPT_SSESSION_TRANSPORT_ERROR;

                /* revert the state back */
                session_ctx->state_handler = state;
                goto err;
            }
        }
    } else {
        res = secure_session_unwrap(session_ctx, in, bytes_received, message, &message_length);
        if (ECRYPT_SUCCESS == res) {
            res = (ssize_t)message_length;
        }
    }

err:

    if (in != stack_buf) {
        free(in);
    }

    return res;
}

bool secure_session_is_established(const secure_session_t* session_ctx)
{
    return (NULL == session_ctx->state_handler);
}

ecrypt_status_t secure_session_get_remote_id(const secure_session_t* session_ctx,
                                             uint8_t* id,
                                             size_t* id_length)
{
    if (!session_ctx || !id_length) {
        return ECRYPT_INVALID_PARAMETER;
    }
    if (!id || (*id_length) < (session_ctx->peer.id_length)) {
        (*id_length) = (session_ctx->peer.id_length);
        return ECRYPT_BUFFER_TOO_SMALL;
    }
    memcpy(id, session_ctx->peer.id, session_ctx->peer.id_length);
    (*id_length) = (session_ctx->peer.id_length);
    return ECRYPT_SUCCESS;
}
