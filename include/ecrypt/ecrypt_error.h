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

/**
 * @file ecrypt/ecrypt_error.h
 * @brief return type, return codes and check macros
 */

#ifndef ECRYPT_ERROR_H
#define ECRYPT_ERROR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <ecconnect/ecconnect_error.h>

/** @brief return type */
typedef int32_t ecrypt_status_t;

/**
 * @addtogroup ECRYPT
 * @{
 * @defgroup ECCONNECT_ERROR_CODES status codes
 * @{
 */

//
#define ECRYPT_SUCCESS ECCONNECT_SUCCESS
#define ECRYPT_SSESSION_SEND_OUTPUT_TO_PEER 1

// errors
#define ECRYPT_FAIL ECCONNECT_FAIL
#define ECRYPT_INVALID_PARAMETER ECCONNECT_INVALID_PARAMETER
#define ECRYPT_NO_MEMORY ECCONNECT_NO_MEMORY
#define ECRYPT_BUFFER_TOO_SMALL ECCONNECT_BUFFER_TOO_SMALL
#define ECRYPT_DATA_CORRUPT ECCONNECT_DATA_CORRUPT
#define ECRYPT_INVALID_SIGNATURE ECCONNECT_INVALID_SIGNATURE
#define ECRYPT_NOT_SUPPORTED ECCONNECT_NOT_SUPPORTED
#define ECRYPT_SSESSION_KA_NOT_FINISHED 19
#define ECRYPT_SSESSION_TRANSPORT_ERROR 20
#define ECRYPT_SSESSION_GET_PUB_FOR_ID_CALLBACK_ERROR 21

#define ECRYPT_SCOMPARE_SEND_OUTPUT_TO_PEER ECRYPT_SSESSION_SEND_OUTPUT_TO_PEER
/** @} */

/**
 * @defgroup ECRYPT_ERROR_OUT routines for error and debug output
 * @{
 */

#ifdef DEBUG
#define ECRYPT_ERROR_OUT(message) ECCONNECT_ERROR_OUT(message)
#define ECRYPT_DEBUG_OUT(message) ECCONNECT_DEBUG_OUT(message)
#else
#define ECRYPT_ERROR_OUT(message)
#define ECRYPT_DEBUG_OUT(message)
#endif

/**@}*/

/**
 * @defgroup ECCONNECT_CHECK_ROUTINES routines for parameters and variables checking
 * @{
 */

#define ECRYPT_CHECK(x) ECCONNECT_CHECK(x)
#define ECRYPT_CHECK_(x) ECCONNECT_CHECK_(x)

#define ECRYPT_CHECK_PARAM(x) ECCONNECT_CHECK_PARAM(x)
#define ECRYPT_CHECK_PARAM_(x) ECCONNECT_CHECK_PARAM_(x)

#define ECRYPT_CHECK_MALLOC(x, y) ECCONNECT_CHECK_MALLOC(x, y)

#define ECRYPT_CHECK_MALLOC_(x) ECCONNECT_CHECK_MALLOC_(x)

#define ECRYPT_CHECK_FREE(x, y) ECCONNECT_CHECK_FREE(x, y)

#define ECRYPT_IF_FAIL(x, y) ECCONNECT_IF_FAIL(x, y)

#define ECRYPT_IF_FAIL_(x, y) ECCONNECT_IF_FAIL_(x, y)

#define ECRYPT_STATUS_CHECK(x, y) ECCONNECT_STATUS_CHECK(x, y)

#define ECRYPT_STATUS_CHECK_FREE(x, y, z) ECCONNECT_STATUS_CHECK_FREE(x, y, z)

#define ECRYPT_CHECK__(cond, on_fail_call) \
    do {                                   \
        if (!(cond)) {                     \
            on_fail_call;                  \
        }                                  \
    } while (0)

/** @}
 * @}
 */

#endif /* ECRYPT_ERROR_H */
