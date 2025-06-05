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

#ifndef ANI_RS_SIM_H
#define ANI_RS_SIM_H

#include <cstdint>
#include "cxx.h"

namespace OHOS {
namespace SimAni {

struct ArktsError;
struct AniLockStatusResponse;
struct AniOperatorConfig;
struct AniIccAccountInfo;

ArktsError getLockState(int32_t slotId, int32_t lockType, int32_t &lockState);

ArktsError unlockPuk(int32_t slotId, rust::String newPin,
                     rust::String puk, AniLockStatusResponse &lockStatusResponse);

ArktsError unlockPin(int32_t slotId, rust::String pin,
                     AniLockStatusResponse &lockStatusResponse);

ArktsError hasSimCard(int32_t slotId, bool &hasCard);

ArktsError isSimActive(int32_t slotId, bool &isActive);

ArktsError getDefaultVoiceSlotId(int32_t &slotId);

ArktsError getOperatorConfigs(int32_t slotId, rust::Vec<AniOperatorConfig> &configValues);

ArktsError getActiveSimAccountInfoList(rust::Vec<AniIccAccountInfo> &accountInfoValues);

ArktsError getSimAccountInfo(int32_t slotId, AniIccAccountInfo &accountInfoValue);

ArktsError getSimState(int32_t slotId, int32_t &simState);

ArktsError getISOCountryCodeForSim(int32_t slotId, rust::String &countryCode);

int32_t getMaxSimCount();

} // namespace SimAni
} // namespace OHOS


#endif