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

#ifndef BASE_PHONE_SERVICE_STUB_H
#define BASE_PHONE_SERVICE_STUB_H

#include "iremote_stub.h"
#include "i_core_service.h"

namespace OHOS {
namespace Telephony {
class CoreServiceStub : public IRemoteStub<ICoreService> {
public:
    CoreServiceStub();
    virtual ~CoreServiceStub() {};
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    void AddHandlerNetWorkToMap();
    void AddHandlerSimToMap();

private:
    using CoreServiceFunc = int32_t (CoreServiceStub::*)(MessageParcel &data, MessageParcel &reply);

    int32_t OnGetPsRadioTech(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetCsRadioTech(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetOperatorNumeric(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetOperatorName(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetSignalInfoList(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetNetworkState(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetRadioState(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetRadioState(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetNetworkSelectionMode(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetNetworkSearchInformation(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetNetworkSelectionMode(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetIsoCountryCodeForNetwork(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetImei(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetMeid(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetUniqueDeviceId(MessageParcel &data, MessageParcel &reply);
    int32_t OnIsNrSupported(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetPsAttachStatus(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetCellInfoList(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetCellLocation(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetNrOptionMode(MessageParcel &data, MessageParcel &reply);
    int32_t OnHasSimCard(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetSimState(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetCardType(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetISOCountryCodeForSim(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetSimSpn(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetSimIccId(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetSimOperatorNumeric(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetIMSI(MessageParcel &data, MessageParcel &reply);
    int32_t OnIsSimActive(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetLocaleFromDefaultSim(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetSimGid1(MessageParcel &data, MessageParcel &reply);

    int32_t OnGetSimSubscriptionInfo(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetDefaultVoiceSlotId(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetDefaultVoiceSlotId(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetPrimarySlotId(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetPrimarySlotId(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetShowNumber(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetShowNumber(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetShowName(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetShowName(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetActiveSimAccountInfoList(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetOperatorConfig(MessageParcel &data, MessageParcel &reply);
    int32_t OnUnlockPin(MessageParcel &data, MessageParcel &reply);
    int32_t OnUnlockPuk(MessageParcel &data, MessageParcel &reply);
    int32_t OnAlterPin(MessageParcel &data, MessageParcel &reply);
    int32_t OnUnlockPin2(MessageParcel &data, MessageParcel &reply);
    int32_t OnUnlockPuk2(MessageParcel &data, MessageParcel &reply);
    int32_t OnAlterPin2(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetLockState(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetLockState(MessageParcel &data, MessageParcel &reply);
    int32_t OnRefreshSimState(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetActiveSim(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetPreferredNetwork(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetPreferredNetwork(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetSimPhoneNumber(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetSimTeleNumberIdentifier(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetVoiceMailInfor(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetVoiceMailNumber(MessageParcel &data, MessageParcel &reply);
    int32_t OnDiallingNumbersGet(MessageParcel &data, MessageParcel &reply);
    int32_t OnAddIccDiallingNumbers(MessageParcel &data, MessageParcel &reply);
    int32_t OnUpdateIccDiallingNumbers(MessageParcel &data, MessageParcel &reply);
    int32_t OnDelIccDiallingNumbers(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetVoiceMailInfo(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetMaxSimCount(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetImsRegStatus(MessageParcel &data, MessageParcel &reply);
    int32_t OnSendEnvelopeCmd(MessageParcel &data, MessageParcel &reply);
    int32_t OnSendTerminalResponseCmd(MessageParcel &data, MessageParcel &reply);
    int32_t OnHasOperatorPrivileges(MessageParcel &data, MessageParcel &reply);
    int32_t OnUnlockSimLock(MessageParcel &data, MessageParcel &reply);

private:
    std::map<uint32_t, CoreServiceFunc> memberFuncMap_;
};
} // namespace Telephony
} // namespace OHOS
#endif // BASE_PHONE_SERVICE_STUB_H
