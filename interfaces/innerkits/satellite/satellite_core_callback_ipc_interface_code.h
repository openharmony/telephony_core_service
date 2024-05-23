/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef SATELLITE_CORE_CALLBACK_INTERFACE_CODE_H
#define SATELLITE_CORE_CALLBACK_INTERFACE_CODE_H

/* SAID:4012 */
namespace OHOS {
namespace Telephony {
enum class SatelliteCoreCallbackInterfaceCode {
    SET_RADIO_STATE_RESPONSE = 0,
    RADIO_STATE_CHANGED,
    SIM_STATE_CHANGED,
    SATELLITE_STATUS_CHANGED,
};

enum SatelliteRadioResponseType {
    DEFAULT_RADIO_RESPONSE = 1,
    RADIO_STATE_INFO,
};

struct SatelliteStatus {
    int32_t slotId = -1;
    int32_t mode = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // SATELLITE_CORE_CALLBACK_INTERFACE_CODE_H
