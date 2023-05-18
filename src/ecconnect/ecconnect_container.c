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

#include "ecconnect/ecconnect_container.h"

#include <limits.h>

#include "ecconnect/ecconnect_crc32.h"
#include "ecconnect/ecconnect_portable_endian.h"

ecconnect_status_t ecconnect_update_container_checksum(ecconnect_container_hdr_t* hdr)
{
    if (!hdr) {
        return ECCONNECT_INVALID_PARAMETER;
    }

    hdr->crc = 0;
    hdr->crc = htobe32(ecconnect_crc32(hdr, be32toh(hdr->size)));

    return ECCONNECT_SUCCESS;
}

ecconnect_status_t ecconnect_verify_container_checksum(const ecconnect_container_hdr_t* hdr)
{
    uint32_t dummy_crc = 0;
    ecconnect_crc32_t crc;

    if (!hdr) {
        return ECCONNECT_INVALID_PARAMETER;
    }

    crc = ecconnect_crc32_create();
    ecconnect_crc32_update(&crc, hdr, sizeof(ecconnect_container_hdr_t) - sizeof(uint32_t));
    ecconnect_crc32_update(&crc, &dummy_crc, sizeof(uint32_t));
    ecconnect_crc32_update(&crc, hdr + 1, ecconnect_container_data_size(hdr));

    if (hdr->crc == htobe32(ecconnect_crc32_final(&crc))) {
        return ECCONNECT_SUCCESS;
    }

    return ECCONNECT_DATA_CORRUPT;
}

uint8_t* ecconnect_container_data(ecconnect_container_hdr_t* hdr)
{
    if (!hdr) {
        return NULL;
    }
    return (uint8_t*)(hdr + 1);
}

const uint8_t* ecconnect_container_const_data(const ecconnect_container_hdr_t* hdr)
{
    if (!hdr) {
        return NULL;
    }
    return (const uint8_t*)(hdr + 1);
}

size_t ecconnect_container_data_size(const ecconnect_container_hdr_t* hdr)
{
    size_t size = 0;
    if (!hdr) {
        return 0;
    }
    size = be32toh(hdr->size);
    if (size < sizeof(ecconnect_container_hdr_t)) {
        return 0;
    }
    return size - sizeof(ecconnect_container_hdr_t);
}

void ecconnect_container_set_data_size(ecconnect_container_hdr_t* hdr, size_t size)
{
    if (!hdr || size > UINT32_MAX - sizeof(ecconnect_container_hdr_t)) {
        return;
    }
    hdr->size = htobe32(size + sizeof(ecconnect_container_hdr_t));
}
