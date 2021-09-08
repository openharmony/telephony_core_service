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
namespace CellularData {
const uint32_t DATA_FLOW_TYPE_NONE = 0;
const uint32_t DATA_STATE_DISCONNECTED = 11;
const uint32_t DATA_STATE_CONNECTING = 12;
const uint32_t DATA_STATE_CONNECTED = 13;
const uint32_t DATA_STATE_SUSPENDED = 14;
const uint32_t RADIO_TECHNOLOGY_UNKNOWN = 99;
const uint32_t RADIO_TECHNOLOGY_GSM = 100;
const uint32_t RADIO_TECHNOLOGY_1XRTT = 101;
const uint32_t RADIO_TECHNOLOGY_WCDMA = 102;
const uint32_t RADIO_TECHNOLOGY_HSPA = 103;
const uint32_t RADIO_TECHNOLOGY_HSPAP = 104;
const uint32_t RADIO_TECHNOLOGY_TD_SCDMA = 105;
const uint32_t RADIO_TECHNOLOGY_EVDO = 106;
const uint32_t RADIO_TECHNOLOGY_EHRPD = 107;
const uint32_t RADIO_TECHNOLOGY_LTE = 108;
const uint32_t RADIO_TECHNOLOGY_LTE_CA = 109;
const uint32_t RADIO_TECHNOLOGY_IWLAN = 110;
const uint32_t RADIO_TECHNOLOGY_NR = 111;

enum HDataRespondCode {
    H_CODE_INVALID_PARAM = -1,
    H_CODE_FAILED = 0,
    H_CODE_SUCCESS = 1,
};
} // namespace CellularData
} // namespace Telephony
} // namespace OHOS
#endif // CELLULAR_DATA_TYPES_H