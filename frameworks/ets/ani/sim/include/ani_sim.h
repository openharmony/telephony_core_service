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
namespace Telephony {
namespace SimAni {

struct ArktsError;
struct AniLockStatusResponse;
struct AniOperatorConfig;
struct AniIccAccountInfo;
struct AniSimAuthenticationResponse;

ArktsError GetLockState(int32_t slotId, int32_t lockType, int32_t &lockState);

ArktsError UnlockPuk(int32_t slotId, rust::String newPin,
                     rust::String puk, AniLockStatusResponse &lockStatusResponse);

ArktsError UnlockPin(int32_t slotId, rust::String pin,
                     AniLockStatusResponse &lockStatusResponse);

ArktsError HasSimCard(int32_t slotId, bool &hasCard);

ArktsError IsSimActive(int32_t slotId, bool &isActive);

ArktsError GetDefaultVoiceSlotId(int32_t &slotId);

ArktsError GetOperatorConfigs(int32_t slotId, rust::Vec<AniOperatorConfig> &configValues);

ArktsError GetActiveSimAccountInfoList(rust::Vec<AniIccAccountInfo> &accountInfoValues);

ArktsError GetSimAccountInfo(int32_t slotId, AniIccAccountInfo &accountInfoValue);

ArktsError GetSimState(int32_t slotId, int32_t &simState);

ArktsError GetISOCountryCodeForSim(int32_t slotId, rust::String &countryCode);

int32_t GetMaxSimCount();

ArktsError GetSimAuthentication(int32_t slotId, int32_t authType, rust::String authData,
    AniSimAuthenticationResponse &simAuthenticationResponse);

ArktsError GetDsdsMode(int32_t &dsdsMode);

ArktsError GetDefaultVoiceSimId(int32_t &simId);

ArktsError GetOpName(int32_t slotId, rust::String &opName);

ArktsError GetOpKey(int32_t slotId, rust::String &opKey);

ArktsError UnlockSimLock(int32_t slotId, int32_t persoLocktype, rust::String password,
    AniLockStatusResponse &lockStatusResponse);

ArktsError SendTerminalResponseCmd(int32_t slotId, rust::String cmd);

ArktsError SendEnvelopeCmd(int32_t slotId, rust::String cmd);

ArktsError AlterPin2(int32_t slotId, const rust::String newPin2, const rust::String oldPin2,
    AniLockStatusResponse &lockStatusResponse);

ArktsError UnlockPuk2(int32_t slotId, const rust::String newPin2, const rust::String puk2,
    AniLockStatusResponse &lockStatusResponse);

ArktsError UnlockPin2(int32_t slotId, const rust::String pin2, AniLockStatusResponse &lockStatusResponse);

ArktsError SetLockState(int32_t slotId, int32_t lockType, const rust::String password, int32_t state,
    AniLockStatusResponse &lockStatusResponse);

ArktsError AlterPin(int32_t slotId, const rust::String newPin, const rust::String oldPin,
    AniLockStatusResponse &lockStatusResponse);

ArktsError GetShowNumber(int32_t slotId, rust::String &showNumber);

ArktsError SetShowNumber(int32_t slotId, rust::String showNumber);

ArktsError GetShowName(int32_t slotId, rust::String &showName);

ArktsError SetShowName(int32_t slotId, rust::String showName);

ArktsError DeactivateSim(int32_t slotId);

ArktsError ActivateSim(int32_t slotId);

ArktsError SetDefaultVoiceSlotId(int32_t slotId);

ArktsError GetImsi(int32_t slotId, rust::String &imsi);

ArktsError IsOperatorSimCard(int32_t slotId, rust::String operatorName, bool &isOperatorCard);

ArktsError GetSimGid1(int32_t slotId, rust::String &simGid1);

ArktsError GetSimTelephoneNumber(int32_t slotId, rust::String &simTelephoneNumber);

ArktsError SetVoiceMailInfo(int32_t slotId, rust::String mailName, rust::String mailNumber);

ArktsError GetVoiceMailNumber(int32_t slotId, rust::String &voiceMailNumber);

ArktsError GetVoiceMailIdentifier(int32_t slotId, rust::String &voiceMailIdentifier);

ArktsError GetSimIccId(int32_t slotId, rust::String &simIccId);

ArktsError GetCardType(int32_t slotId, int32_t &cardType);

ArktsError GetSimSpn(int32_t slotId, rust::String &simSpn);

ArktsError GetSimOperatorNumeric(int32_t slotId, rust::String &simOperatorNumeric);

ArktsError HasOperatorPrivileges(int32_t slotId, bool &hasPrivileges);
} // namespace SimAni
} // namespace Telephony
} // namespace OHOS


#endif