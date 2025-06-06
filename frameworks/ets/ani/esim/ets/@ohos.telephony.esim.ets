/*
 * Copyright (C) 2025-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { BusinessError } from '@ohos.base'

export default namespace eSIM {
  loadLibrary("esim_ani")

  export native function nativeResetMemory(slotId: int, options?:ResetOption): ResultCode;

  export function resetMemory(slotId: int, options?:ResetOption): Promise<ResultCode> {
    return new Promise<ResultCode>((resolve, reject) => {
      let p = taskpool.execute(nativeResetMemory, slotId, options)
        p.then((e: NullishType) => {
          let r = e as ResultCode
          resolve(r)
        }).catch((e: Error): void => {
          reject(e)
        })
    })
  }

  export enum ResetOption {
    DELETE_OPERATIONAL_PROFILES = 1,

    DELETE_FIELD_LOADED_TEST_PROFILES = 1 << 1,

    RESET_DEFAULT_SMDP_ADDRESS = 1 << 2,
  }

  export enum ResultCode {
    RESULT_SOLVABLE_ERRORS = -2,

    RESULT_MUST_DISABLE_PROFILE = -1,

    RESULT_OK = 0,

    RESULT_GET_EID_FAILED = 201,

    RESULT_ACTIVATION_CODE_CHANGED = 203,

    RESULT_ACTIVATION_CODE_INVALID = 204,

    RESULT_SMDP_ADDRESS_INVALID = 205,

    RESULT_EUICC_INFO_INVALID = 206,

    RESULT_TLS_HANDSHAKE_FAILED = 207,

    RESULT_CERTIFICATE_IO_ERROR = 208,

    RESULT_CERTIFICATE_RESPONSE_TIMEOUT = 209,

    RESULT_AUTHENTICATION_FAILED = 210,

    RESULT_RESPONSE_HTTP_FAILED = 211,

    RESULT_CONFIRMATION_CODE_INCORRECT = 212,

    RESULT_EXCEEDED_CONFIRMATION_CODE_TRY_LIMIT = 213,

    RESULT_NO_PROFILE_ON_SERVER = 214,

    RESULT_TRANSACTION_ID_INVALID = 215,

    RESULT_SERVER_ADDRESS_INVALID = 216,

    RESULT_GET_BOUND_PROFILE_PACKAGE_FAILED = 217,

    RESULT_USER_CANCEL_DOWNLOAD = 218,

    RESULT_SERVER_UNAVAILABLE = 220,

    RESULT_PROFILE_NON_DELETE = 223,

    RESULT_SMDP_ADDRESS_INCORRECT = 226,

    RESULT_ANALYZE_AUTHENTICATION_SERVER_RESPONSE_FAILED = 228,

    RESULT_ANALYZE_AUTHENTICATION_CLIENT_RESPONSE_FAILED = 229,

    RESULT_ANALYZE_AUTHENTICATION_CLIENT_MATCHING_ID_REFUSED = 231,

    RESULT_PROFILE_TYPE_ERROR_AUTHENTICATION_STOPPED = 233,

    RESULT_CARRIER_SERVER_REFUSED_ERRORS = 249,

    RESULT_CERTIFICATE_INVALID = 251,

    RESULT_OUT_OF_MEMORY = 263,

    RESULT_PPR_FORBIDDEN = 268,

    RESULT_NOTHING_TO_DELETE = 270,

    RESULT_PPR_NOT_MATCH = 276,

    RESULT_CAT_BUSY = 283,

    RESULT_PROFILE_EID_INVALID = 284,

    RESULT_DOWNLOAD_TIMEOUT = 287,

    RESULT_SGP_22_OTHER = 400,
  }
}
