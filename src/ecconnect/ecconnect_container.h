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

#ifndef ECCONNECT_CONTAINER_H
#define ECCONNECT_CONTAINER_H

#include <ecconnect/ecconnect_api.h>
#include <ecconnect/ecconnect_error.h>

#define ECCONNECT_CONTAINER_TAG_LENGTH 4

#pragma pack(push, 1)
struct ecconnect_container_hdr_type {
    char tag[ECCONNECT_CONTAINER_TAG_LENGTH];
    uint32_t size; /* Size is data + sizeof(ecconnect_container_hdr_t), so should be not less than
                      sizeof(ecconnect_container_hdr_t). Network byte order. */
    uint32_t crc;
};
#pragma pack(pop)

typedef struct ecconnect_container_hdr_type ecconnect_container_hdr_t;

ECCONNECT_API
ecconnect_status_t ecconnect_update_container_checksum(ecconnect_container_hdr_t* hdr);

ECCONNECT_API
ecconnect_status_t ecconnect_verify_container_checksum(const ecconnect_container_hdr_t* hdr);

ECCONNECT_API
uint8_t* ecconnect_container_data(ecconnect_container_hdr_t* hdr);

ECCONNECT_API
const uint8_t* ecconnect_container_const_data(const ecconnect_container_hdr_t* hdr);

ECCONNECT_API
size_t ecconnect_container_data_size(const ecconnect_container_hdr_t* hdr);

ECCONNECT_API
void ecconnect_container_set_data_size(ecconnect_container_hdr_t* hdr, size_t size);

#endif /* ECCONNECT_CONTAINER_H */
