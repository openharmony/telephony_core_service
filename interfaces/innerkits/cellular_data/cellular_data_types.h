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

#ifndef CELLULAR_DATA_TYPES_H
#define CELLULAR_DATA_TYPES_H

#include <cstdint>

namespace OHOS {
namespace Telephony {
enum class DataConnectionStatus : int32_t {
    DATA_STATE_DISCONNECTED = 11,
    DATA_STATE_CONNECTING = 12,
    DATA_STATE_CONNECTED = 13,
    DATA_STATE_SUSPENDED = 14
};

enum class DataRespondCode : int32_t {
    SET_FAILED = 0,
    SET_SUCCESS = 1
};

enum class DataSwitchCode : int32_t {
    CELLULAR_DATA_DISABLED = 0,
    CELLULAR_DATA_ENABLED = 1
};

enum class RoamingSwitchCode : int32_t {
    CELLULAR_DATA_ROAMING_DISABLED = 0,
    CELLULAR_DATA_ROAMING_ENABLED = 1
};

enum class RequestNetCode : int32_t {
    REQUEST_FAILED = 0,
    REQUEST_SUCCESS = 1
};

enum class ReleaseNetCode : int32_t {
    RELEASE_FAILED = 0,
    RELEASE_SUCCESS = 1
};

enum class CellDataFlowType : int32_t {
    DATA_FLOW_TYPE_NONE = 0,
    DATA_FLOW_TYPE_DOWN = 1,
    DATA_FLOW_TYPE_UP = 2,
    DATA_FLOW_TYPE_UP_DOWN = 3,
    DATA_FLOW_TYPE_DORMANT = 4
};
} // namespace Telephony
} // namespace OHOS
#endif // CELLULAR_DATA_TYPES_H