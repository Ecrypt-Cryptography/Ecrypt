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

#include "ecconnect/ecconnect_rand.h"

#include <limits.h>

#include <openssl/rand.h>

#include "ecconnect/ecconnect_wipe.h"

ecconnect_status_t ecconnect_rand(uint8_t* buffer, size_t length)
{
    int result;

    if (!buffer || !length || length > INT_MAX) {
        return ECCONNECT_INVALID_PARAMETER;
    }

    result = RAND_bytes(buffer, (int)length);

    if (result == 1) {
        return ECCONNECT_SUCCESS;
    }

    /*
     * Make sure we don't leak PRNG state in case the buffer has been
     * partially filled and we have to return an error.
     */
    ecconnect_wipe(buffer, length);

    return (result < 0) ? ECCONNECT_NOT_SUPPORTED : ECCONNECT_FAIL;
}
