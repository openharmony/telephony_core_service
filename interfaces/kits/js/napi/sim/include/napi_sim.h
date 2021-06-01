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

#ifndef NAPI_SIM_H
#define NAPI_SIM_H
#include <codecvt>
#include <locale>
#include <string>

#include "napi/native_api.h"
#include "napi/native_node_api.h"
namespace OHOS {
namespace TelephonyNapi {
#define GET_PARAMS(env, info, num) \
    size_t argc = num;             \
    napi_value argv[num];          \
    napi_value thisVar;            \
    void *data;                    \
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data)

const int DEFAULT_ERROR = -1;
const int RESOLVED = 1;
const int REJECT = 0;
const int NONE_PARAMTER = 0;
const int TWO_PARAMETER = 2;

struct AsyncContext {
    napi_env env;
    napi_async_work work;
    int32_t slotId;
    napi_value value;
    size_t valueLen;
    napi_deferred deferred;
    napi_ref callbackRef;
    int status;
};

enum SimState {
    /**
     * Indicates unknown SIM card state, that is, the accurate status cannot be obtained.
     */
    SIM_STATE_UNKNOWN,

    /**
     * Indicates that the SIM card is in the <b>not present</b> state, that is, no SIM card is inserted
     * into the card slot.
     */
    SIM_STATE_NOT_PRESENT,

    /**
     * Indicates that the SIM card is in the <b>locked</b> state, that is, the SIM card is locked by the
     * personal identification number (PIN)/PIN unblocking key (PUK) or network.
     */
    SIM_STATE_LOCKED,

    /**
     * Indicates that the SIM card is in the <b>not ready</b> state, that is, the SIM card is in position
     * but cannot work properly.
     */
    SIM_STATE_NOT_READY,

    /**
     * Indicates that the SIM card is in the <b>ready</b> state, that is, the SIM card is in position and
     * is working properly.
     */
    SIM_STATE_READY,

    /**
     * Indicates that the SIM card is in the <b>loaded</b> state, that is, the SIM card is in position and
     * is working properly.
     */
    SIM_STATE_LOADED
};
} // namespace TelephonyNapi
} // namespace OHOS
#endif // NAPI_SIM_H