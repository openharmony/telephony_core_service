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

#ifndef OHOS_NAPI_SIM_H
#define OHOS_NAPI_SIM_H

#include <array>
#include <string>
#include <vector>
#include "base_context.h"
#include "sim_state_type.h"
#include "telephony_napi_common_error.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {
constexpr size_t ARRAY_SIZE = 64;
constexpr size_t IMSI_LOG_LENGTH = 6;
constexpr size_t kMaxNumberLen = 100;

template<typename T>
struct AsyncContext {
    BaseContext context;
    int32_t slotId = ERROR_DEFAULT;
    T callbackVal;
};

struct AsyncContext2 {
    AsyncContext<bool> asyncContext;
    std::array<char, ARRAY_SIZE> inputStr {};
};

struct AsyncContextPIN {
    AsyncContext<napi_value> asyncContext;
    int32_t result = ERROR_DEFAULT;
    int32_t remain = ERROR_DEFAULT;
    int32_t pinEnable = ERROR_DEFAULT;
    std::string inStr1 {};
    std::string inStr2 {};
};

struct AsyncIccAccountInfo {
    AsyncContext<napi_value> asyncContext;
    std::vector<IccAccountInfo> vecInfo;
};

struct ConfigInfo {
    std::string field {};
    std::string value {};
};

struct AsyncOperatorConfig {
    AsyncContext<napi_value> asyncContext;
    std::vector<ConfigInfo> configValue {};
};

struct TelNumbersInfo {
    int32_t recordNumber = ERROR_NONE;
    std::array<char, ARRAY_SIZE> alphaTag {};
    std::array<char, ARRAY_SIZE> number {};
    std::array<char, ARRAY_SIZE> pin2 {};
};

template<typename T>
struct AsyncDiallingNumbers {
    AsyncContext<T> asyncContext;
    int32_t type = ERROR_DEFAULT;
    std::vector<TelNumbersInfo> infoVec;
};

struct AsyncVoiceMail {
    AsyncContext<bool> asyncContext;
    std::array<char, ARRAY_SIZE> mailName {};
    std::array<char, ARRAY_SIZE> mailNumber {};
};

struct AsyncGetLockState {
    AsyncContext<int32_t> asyncContext;
    int32_t lockType = ERROR_DEFAULT;
};

struct AsyncDefaultSlotId {
    AsyncContext<int32_t> asyncContext;
};

struct AsyncStkCallSetupResult {
    AsyncContext<bool> asyncContext;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_NAPI_SIM_H
