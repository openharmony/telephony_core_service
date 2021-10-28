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

#ifndef NAPI_SIM_INCLUDE_NAPI_SIM_H
#define NAPI_SIM_INCLUDE_NAPI_SIM_H

#include <array>
#include <string>
#include <unordered_map>
#include "base_context.h"
#include "i_sim_manager.h"
#include "napi_util.h"
#include "telephony_log_wrapper.h"
#include "core_manager.h"

namespace OHOS {
namespace Telephony {
namespace {
constexpr int32_t DEFAULT_ERROR = -1;
constexpr size_t ARRAY_SIZE = 32;
} // namespace

template<typename T>
struct AsyncContext {
    BaseContext context;
    int32_t slotId = CoreManager::DEFAULT_SLOT_ID;
    T callbackVal;
};

template<typename T>
struct AsyncContext2 {
    AsyncContext<T> value;
    std::array<char, ARRAY_SIZE> inputStr {};
};

struct AsyncContextPIN {
    AsyncContext<napi_value> pinContext;
    int32_t result = DEFAULT_ERROR;
    int32_t remain = DEFAULT_ERROR;
    int32_t pinEnable = DEFAULT_ERROR;
    std::array<char, ARRAY_SIZE> pin {};
    std::array<char, ARRAY_SIZE> puk {};
};

struct AsyncIccAccountInfo {
    AsyncContext<napi_value> asyncContext;
    std::vector<IccAccountInfo> vecInfo;
};

struct TelNumbersInfo {
    int32_t recordNumber = DEFAULT_ERROR;
    std::array<char, ARRAY_SIZE> alphaTag {};
    std::array<char, ARRAY_SIZE> number {};
};

template<typename T>
struct AsyncPhoneBook {
    AsyncContext<T> asyncContext;
    int32_t type = DEFAULT_ERROR;
    int32_t index = DEFAULT_ERROR;
    std::vector<TelNumbersInfo> infoVec;
};

struct AsyncDelPhoneBook {
    AsyncContext<bool> asyncContext;
    int32_t type = DEFAULT_ERROR;
    int32_t index = DEFAULT_ERROR;
};
} // namespace Telephony
} // namespace OHOS
#endif // NAPI_SIM_H