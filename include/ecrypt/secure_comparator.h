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

#ifndef ECRYPT_SECURE_COMPARATOR_H
#define ECRYPT_SECURE_COMPARATOR_H

#include <ecrypt/ecrypt_api.h>
#include <ecrypt/ecrypt_error.h>

#define ECRYPT_SCOMPARE_MATCH 21
#define ECRYPT_SCOMPARE_NO_MATCH 22
#define ECRYPT_SCOMPARE_NOT_READY 0

#ifdef __cplusplus
extern "C" {
#endif

typedef struct secure_comparator_type secure_comparator_t;

ECRYPT_API
secure_comparator_t* secure_comparator_create(void);

ECRYPT_API
ecrypt_status_t secure_comparator_destroy(secure_comparator_t* comp_ctx);

ECRYPT_API
ecrypt_status_t secure_comparator_append_secret(secure_comparator_t* comp_ctx,
                                                const void* secret_data,
                                                size_t secret_data_length);

ECRYPT_API
ecrypt_status_t secure_comparator_begin_compare(secure_comparator_t* comp_ctx,
                                                void* compare_data,
                                                size_t* compare_data_length);

ECRYPT_API
ecrypt_status_t secure_comparator_proceed_compare(secure_comparator_t* comp_ctx,
                                                  const void* peer_compare_data,
                                                  size_t peer_compare_data_length,
                                                  void* compare_data,
                                                  size_t* compare_data_length);

ECRYPT_API
ecrypt_status_t secure_comparator_get_result(const secure_comparator_t* comp_ctx);

#ifdef __cplusplus
}
#endif

#endif /* ECRYPT_SECURE_COMPARATOR_H */
