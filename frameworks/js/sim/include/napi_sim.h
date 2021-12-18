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
#include "i_sim_account_manager.h"

namespace OHOS {
namespace Telephony {
namespace {
constexpr int32_t DEFAULT_ERROR = -1;
constexpr size_t ARRAY_SIZE = 64;
} // namespace

template<typename T>
struct AsyncContext {
    BaseContext context;
    int32_t slotId = DEFAULT_ERROR;
    T callbackVal;
};

template<typename T>
struct AsyncContext2 {
    AsyncContext<T> aContext;
    std::array<char, ARRAY_SIZE> inputStr {};
};

struct AsyncContextPIN {
    AsyncContext<napi_value> pinContext;
    int32_t result = DEFAULT_ERROR;
    int32_t remain = DEFAULT_ERROR;
    int32_t pinEnable = DEFAULT_ERROR;
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
    int32_t recordNumber = DEFAULT_ERROR;
    std::array<char, ARRAY_SIZE> alphaTag {};
    std::array<char, ARRAY_SIZE> number {};
    std::array<char, ARRAY_SIZE> pin2 {};
};

template<typename T>
struct AsyncDiallingNumbers {
    AsyncContext<T> asyncContext;
    int32_t type = DEFAULT_ERROR;
    std::vector<TelNumbersInfo> infoVec;
};

struct AsyncVoiceMail {
    AsyncContext<bool> asyncContext;
    std::array<char, ARRAY_SIZE> mailName {};
    std::array<char, ARRAY_SIZE> mailNumber {};
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_NAPI_SIM_H