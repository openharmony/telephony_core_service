/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#ifndef RIL_COMMON_H
#define RIL_COMMON_H

#include <string>

typedef enum {
    CORE_SERVICE_NO_PHONE = 0,
    CORE_SERVICE_GSM_PHONE = 1,
    CORE_SERVICE_CDMA_PHONE = 2,
    CORE_SERVICE_CDMA_LTE_PHONE = 3
} CoreServiceTelephonyType;

typedef enum {
    HDF_SUCCESS = 0, /**< The operation is successful. */
    HDF_FAILURE = -1, /**< Failed to invoke the OS underlying function. */
    HDF_ERR_NOT_SUPPORT = -2, /**< Not supported. */
    HDF_ERR_INVALID_PARAM = -3, /**< Invalid parameter. */
} HDF_STATUS;

typedef enum { CORE_SERVICE_ERROR = 0, CORE_SERVICE_SUCCESS = 1 } CoreServiceLteOptStatus;
#endif