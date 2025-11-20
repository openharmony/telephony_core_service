/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef ANI_RADIO_TYPES_H
#define ANI_RADIO_TYPES_H

#include <variant>
#include "ffrt.h"
#include "telephony_types.h"
#include "telephony_errors.h"
#include "network_search_types.h"
#include "network_search_result.h"

namespace OHOS {
namespace Telephony {
constexpr int WAIT_TIME_SECOND = 60 * 3;
constexpr int WAIT_NETWORK_MANUAL_SEARCH_TIME_SECOND = 60 * 5;

static const std::string RADIO_TECH_NAME_GSM = "GSM";
static const std::string RADIO_TECH_NAME_GPRS = "GPRS";
static const std::string RADIO_TECH_NAME_WCDMA = "WCDMA";
static const std::string RADIO_TECH_NAME_LTE = "LTE";
static const std::string RADIO_TECH_NAME_NR = "NR";

enum EtsNetworkSelectionMode {
    ETS_NETWORK_SELECTION_UNKNOWN,
    ETS_NETWORK_SELECTION_AUTOMATIC,
    ETS_NETWORK_SELECTION_MANUAL
};

enum NetworkCapabilityType {
    SERVICE_TYPE_LTE,
    SERVICE_TYPE_NR,
};

enum NetworkCapabilityState {
    SERVICE_CAPABILITY_OFF,
    SERVICE_CAPABILITY_ON,
};

using AniCallbackResultType = std::variant<bool, int32_t, std::string, sptr<NetworkSearchResult>>;

struct AniCallbackContext {
    ffrt::mutex callbackMutex;
    ffrt::condition_variable cv;
    bool isCallbackComplete = false;
    int32_t errorCode = OHOS::Telephony::TELEPHONY_ERR_SUCCESS;
    AniCallbackResultType result;
};
}
}
#endif