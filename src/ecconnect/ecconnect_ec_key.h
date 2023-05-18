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

#ifndef ECCONNECT_EC_KEY_H
#define ECCONNECT_EC_KEY_H

#include <ecconnect/ecconnect_container.h>
#include <ecconnect/ecconnect_error.h>

/** private key header part */
#define EC_PRIV_KEY_PREF "REC"
/** public key header part */
#define EC_PUB_KEY_PREF "UEC"

/** elliptic curve header part for 256bits key*/
#define EC_256 "2"
/** @brief elliptic curve header part for 384bits key*/
#define EC_384 "3"
/** @brief elliptic curve header part for 521bits key*/
#define EC_521 "5"

#define EC_SIZE_TAG_256 '2'
#define EC_SIZE_TAG_384 '3'
#define EC_SIZE_TAG_521 '5'

#define EC_KEY_SUF(_KEY_SIZE_) EC_##_KEY_SIZE_

#define EC_PRIV_KEY_TAG(_KEY_SIZE_) (EC_PRIV_KEY_PREF EC_KEY_SUF(_KEY_SIZE_))
#define EC_PUB_KEY_TAG(_KEY_SIZE_) (EC_PUB_KEY_PREF EC_KEY_SUF(_KEY_SIZE_))

#define EC_BYTE_SIZE(_KEY_SIZE_) (((_KEY_SIZE_) + 7) / 8)

#define EC_PRIV_SIZE(_KEY_SIZE_) EC_BYTE_SIZE(_KEY_SIZE_)
#define EC_PUB_SIZE(_KEY_SIZE_) (EC_BYTE_SIZE(_KEY_SIZE_) + 1)
#define EC_PUB_UNCOMPRESSED_SIZE(_KEY_SIZE_) (2 * EC_BYTE_SIZE(_KEY_SIZE_) + 1)

#define DECLARE_EC_PUBLIC_KEY(_KEY_SIZE_)         \
    struct ecconnect_ec_pub_key_##_KEY_SIZE_##_type { \
        ecconnect_container_hdr_t hdr;                \
        uint8_t d[EC_PUB_SIZE(_KEY_SIZE_)];       \
    };                                            \
                                                  \
    typedef struct ecconnect_ec_pub_key_##_KEY_SIZE_##_type ecconnect_ec_pub_key_##_KEY_SIZE_##_t

/* struct members are ordered this way to avoid struct member alignment on different platforms */
#define DECLARE_EC_PRIVATE_KEY(_KEY_SIZE_)         \
    struct ecconnect_ec_priv_key_##_KEY_SIZE_##_type { \
        ecconnect_container_hdr_t hdr;                 \
        uint8_t Q[EC_PRIV_SIZE(_KEY_SIZE_)];       \
    };                                             \
                                                   \
    typedef struct ecconnect_ec_priv_key_##_KEY_SIZE_##_type ecconnect_ec_priv_key_##_KEY_SIZE_##_t

#define DECLARE_EC_KEY(_KEY_SIZE_)     \
    DECLARE_EC_PUBLIC_KEY(_KEY_SIZE_); \
    DECLARE_EC_PRIVATE_KEY(_KEY_SIZE_)

DECLARE_EC_KEY(256);
DECLARE_EC_KEY(384);
DECLARE_EC_KEY(521);

/* This is considered internal API */
typedef void ecconnect_engine_specific_ec_key_t;

ecconnect_status_t ecconnect_ec_pub_key_to_engine_specific(const ecconnect_container_hdr_t* key,
                                                   size_t key_length,
                                                   ecconnect_engine_specific_ec_key_t** engine_key);
ecconnect_status_t ecconnect_ec_priv_key_to_engine_specific(const ecconnect_container_hdr_t* key,
                                                    size_t key_length,
                                                    ecconnect_engine_specific_ec_key_t** engine_key);
ecconnect_status_t ecconnect_engine_specific_to_ec_priv_key(const ecconnect_engine_specific_ec_key_t* engine_key,
                                                    ecconnect_container_hdr_t* key,
                                                    size_t* key_length);
ecconnect_status_t ecconnect_engine_specific_to_ec_pub_key(const ecconnect_engine_specific_ec_key_t* engine_key,
                                                   bool compressed,
                                                   ecconnect_container_hdr_t* key,
                                                   size_t* key_length);

ecconnect_status_t ecconnect_ec_pub_key_check_length(const ecconnect_container_hdr_t* key, size_t key_length);
ecconnect_status_t ecconnect_ec_priv_key_check_length(const ecconnect_container_hdr_t* key, size_t key_length);

#endif /* ECCONNECT_EC_KEY_H */
