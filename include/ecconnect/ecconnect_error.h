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
 * @file ecconnect/ecconnect_error.h
 * @brief ecconnect return type, return codes and check macros
 *
 */
#ifndef ECCONNECT_ERROR_H
#define ECCONNECT_ERROR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/** @brief return type */
typedef int32_t ecconnect_status_t;

/**
 * @addtogroup ecconnect
 * @{
 * @defgroup ECCONNECT_ERROR_CODES status codes
 * @{
 */

#define ECCONNECT_SUCCESS 0 // success code

// error codes
#define ECCONNECT_FAIL 11
#define ECCONNECT_INVALID_PARAMETER 12
#define ECCONNECT_NO_MEMORY 13
#define ECCONNECT_BUFFER_TOO_SMALL 14
#define ECCONNECT_DATA_CORRUPT 15
#define ECCONNECT_INVALID_SIGNATURE 16
#define ECCONNECT_NOT_SUPPORTED 17
#define ECCONNECT_ENGINE_FAIL 18

/** @} */

/**
 * @defgroup ECCONNECT_ERROR_OUT routines for error and debug output
 * @{
 */

#ifdef DEBUG
#define ECCONNECT_ERROR_OUT(message) fprintf(stderr, "%s:%u - error: %s\n", __FILE__, __LINE__, message)
#define ECCONNECT_DEBUG_OUT(message) fprintf(stdout, "%s:%u - debug: %s\n", __FILE__, __LINE__, message)
#else
#define ECCONNECT_ERROR_OUT(message)
#define ECCONNECT_DEBUG_OUT(message)
#endif

#ifndef UNUSED
#define UNUSED(x) (void)(x)
#endif

#ifndef DEPRECATED
#if __cplusplus >= 201402L
#define DEPRECATED(msg) [[deprecated(msg)]]
#elif defined(__GNUC__) || defined(__clang__)
#define DEPRECATED(msg) __attribute__((deprecated(msg)))
#else
#define DEPRECATED(msg)
#endif
#endif

#if __cplusplus >= 201402L
#define ECCONNECT_MUST_USE [[nodiscard]]
#elif defined(__GNUC__) || defined(__clang__)
#define ECCONNECT_MUST_USE __attribute__((warn_unused_result))
#else
#define ECCONNECT_MUST_USE
#endif

/**@}*/

/**
 * @defgroup ECCONNECT_CHECK_ROUTINES routines for parameters and variables checking
 * @{
 */
#define ECCONNECT_CHECK(x)       \
    if (!(x)) {              \
        ECCONNECT_ERROR_OUT(#x); \
        return ECCONNECT_FAIL;   \
    }

#define ECCONNECT_CHECK_(x)      \
    if (!(x)) {              \
        ECCONNECT_ERROR_OUT(#x); \
        return NULL;         \
    }

#define ECCONNECT_CHECK_PARAM(x)            \
    if (!(x)) {                         \
        ECCONNECT_ERROR_OUT(#x);            \
        return ECCONNECT_INVALID_PARAMETER; \
    }

#define ECCONNECT_CHECK_PARAM_(x) \
    if (!(x)) {               \
        ECCONNECT_ERROR_OUT(#x);  \
        return NULL;          \
    }

#define ECCONNECT_CHECK_MALLOC(x, y) \
    y = malloc(sizeof(x));       \
    if (!(x)) {                  \
        ECCONNECT_ERROR_OUT(#x);     \
        return ECCONNECT_NO_MEMORY;  \
    }

#define ECCONNECT_CHECK_MALLOC_(x) \
    if (!(x)) {                \
        ECCONNECT_ERROR_OUT(#x);   \
        return NULL;           \
    }

#define ECCONNECT_CHECK_MALLOC_(x) \
    if (!(x)) {                \
        ECCONNECT_ERROR_OUT(#x);   \
        return NULL;           \
    }

#define ECCONNECT_CHECK_FREE(x, y) \
    if (!(x)) {                \
        ECCONNECT_ERROR_OUT(#x);   \
        free(y);               \
        return ECCONNECT_FAIL;     \
    }

#define ECCONNECT_IF_FAIL(x, y)  \
    if (!(x)) {              \
        ECCONNECT_ERROR_OUT(#x); \
        {                    \
            y;               \
        }                    \
        return ECCONNECT_FAIL;   \
    }

#define ECCONNECT_IF_FAIL_(x, y) \
    if (!(x)) {              \
        ECCONNECT_ERROR_OUT(#x); \
        {                    \
            y;               \
        }                    \
        return NULL;         \
    }

#define ECCONNECT_STATUS_CHECK(x, y) \
    {                            \
        ecconnect_status_t res = x;  \
        if (res != (y)) {        \
            ECCONNECT_ERROR_OUT(#x); \
            return res;          \
        }                        \
    }

#define ECCONNECT_STATUS_CHECK_FREE(x, y, z) \
    {                                    \
        ecconnect_status_t res = x;          \
        if (res != (y)) {                \
            ECCONNECT_ERROR_OUT(#x);         \
            free(z);                     \
            return res;                  \
        }                                \
    }

/** @}
 * @}
 */
#endif /* ECCONNECT_ERROR_H */
