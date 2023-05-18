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

#ifndef ECCONNECT_SIGN_RSA_H
#define ECCONNECT_SIGN_RSA_H

#include <ecconnect/ecconnect_asym_sign.h>
#include <ecconnect/ecconnect_error.h>

ecconnect_status_t ecconnect_sign_init_rsa_pss_pkcs8(ecconnect_sign_ctx_t* ctx,
                                             const void* private_key,
                                             size_t private_key_length,
                                             const void* public_key,
                                             size_t public_key_length);
ecconnect_status_t ecconnect_sign_update_rsa_pss_pkcs8(ecconnect_sign_ctx_t* ctx, const void* data, size_t data_length);
ecconnect_status_t ecconnect_sign_final_rsa_pss_pkcs8(ecconnect_sign_ctx_t* ctx,
                                              void* signature,
                                              size_t* signature_length);
ecconnect_status_t ecconnect_sign_export_key_rsa_pss_pkcs8(const ecconnect_sign_ctx_t* ctx,
                                                   void* key,
                                                   size_t* key_length,
                                                   bool isprivate);
ecconnect_status_t ecconnect_sign_cleanup_rsa_pss_pkcs8(ecconnect_sign_ctx_t* ctx);

ecconnect_status_t ecconnect_verify_init_rsa_pss_pkcs8(ecconnect_sign_ctx_t* ctx,
                                               const void* private_key,
                                               size_t private_key_length,
                                               const void* public_key,
                                               size_t public_key_length);
ecconnect_status_t ecconnect_verify_update_rsa_pss_pkcs8(ecconnect_sign_ctx_t* ctx,
                                                 const void* data,
                                                 size_t data_length);
ecconnect_status_t ecconnect_verify_final_rsa_pss_pkcs8(ecconnect_sign_ctx_t* ctx,
                                                const void* signature,
                                                size_t signature_length);
ecconnect_status_t ecconnect_verify_cleanup_rsa_pss_pkcs8(ecconnect_sign_ctx_t* ctx);

#endif /*ECCONNECT_SIGN_RSA_H*/
