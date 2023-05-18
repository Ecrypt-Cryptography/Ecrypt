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
 * @file ecconnect.h
 *
 * @brief main interface of ecconnect
 * @see ecconnect in wiki
 */
#ifndef ECCONNECT_H
#define ECCONNECT_H

/**
 * @defgroup ecconnect ecconnect
 * @brief ecconnect is a cross-platform multipurpose cryptographic library. It provides a set of highly
 * secure cryptographic primitives through a well-defined, consistent and simple interface.
 * @{
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <ecconnect/ecconnect_asym_cipher.h>
#include <ecconnect/ecconnect_asym_ka.h>
#include <ecconnect/ecconnect_asym_sign.h>
#include <ecconnect/ecconnect_error.h>
#include <ecconnect/ecconnect_hash.h>
#include <ecconnect/ecconnect_hmac.h>
#include <ecconnect/ecconnect_kdf.h>
#include <ecconnect/ecconnect_rand.h>
#include <ecconnect/ecconnect_rsa_key_pair_gen.h>
#include <ecconnect/ecconnect_sym.h>
#include <ecconnect/ecconnect_wipe.h>

/**@}*/
#endif /* ECCONNECT_H */
