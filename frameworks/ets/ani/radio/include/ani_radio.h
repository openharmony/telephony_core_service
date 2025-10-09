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

#ifndef ANI_RS_RADIO_H
#define ANI_RS_RADIO_H

#include <cstdint>
#include "cxx.h"
#include "ims_reg_info_callback_stub.h"

namespace OHOS {
namespace RadioAni {
struct ArktsError;
struct ImsRegInfoAni;
struct SignalInformationAni;
struct NetworkStateAni;

ArktsError GetImsRegInfo(int32_t slotId, int32_t imsSrvType, ImsRegInfoAni &imsRegInfo);
ArktsError GetSignalInformation(int32_t slotId, rust::Vec<SignalInformationAni> &signalInfoList);
ArktsError GetPrimarySlotId(int32_t &slotId);
ArktsError GetNetworkState(int32_t slotId, NetworkStateAni &networkState);
bool IsNrSupported();

ArktsError EventListenerRegister(int32_t slotId, int32_t imsSrvType);
ArktsError EventListenerUnRegister(int32_t slotId, int32_t imsSrvType);

class AniImsRegInfoCallback : public Telephony::ImsRegInfoCallbackStub {
public:
    int32_t OnImsRegInfoChanged(int32_t slotId, Telephony::ImsServiceType imsSrvType,
        const Telephony::ImsRegInfo &info) override;
};

} // namespace RadioAni
} // namespace OHOS

#endif
