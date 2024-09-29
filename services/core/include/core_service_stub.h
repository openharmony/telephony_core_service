/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include "i_core_service.h"
#include "iremote_stub.h"
#include "core_service_ipc_interface_code.h"

namespace OHOS {
namespace Telephony {
class CoreServiceStub : public IRemoteStub<ICoreService> {
public:
    CoreServiceStub();
    virtual ~CoreServiceStub() {}
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    void AddHandlerNetWorkToMap();
    void AddHandlerDeviceToMap();
    void AddHandlerImsToMap();
    void AddHandlerSimToMap();
    void AddHandlerSimLockToMap();
    void AddHandlerSimToMapExt();
    void AddHandlerVoiceMailToMap();
    void AddHandlerPdpProfileToMap();
    void AddHandlerOpkeyVersionToMap();
    int32_t SetTimer(uint32_t code);
    void CancelTimer(int32_t id);

private:
    using CoreServiceFunc = std::function<int32_t(MessageParcel &data, MessageParcel &reply)>;

    int32_t OnGetPsRadioTech(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetCsRadioTech(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetOperatorNumeric(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetResidentNetworkNumeric(MessageParcel &data, MessageParcel &reply);
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
    int32_t OnGetImeiSv(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetMeid(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetUniqueDeviceId(MessageParcel &data, MessageParcel &reply);
    int32_t OnIsNrSupported(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetCellInfoList(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetCellLocation(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetNrOptionMode(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetNrOptionMode(MessageParcel &data, MessageParcel &reply);
    int32_t OnHasSimCard(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetSimState(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetDsdsMode(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetCardType(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetISOCountryCodeForSim(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetSimSpn(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetSimIccId(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetSimOperatorNumeric(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetIMSI(MessageParcel &data, MessageParcel &reply);
    int32_t OnIsCTSimCard(MessageParcel &data, MessageParcel &reply);
    int32_t OnIsSimActive(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetSlotId(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetSimId(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetLocaleFromDefaultSim(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetSimGid1(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetSimGid2(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetSimEons(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetOpName(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetOpKey(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetOpKeyExt(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetSimSubscriptionInfo(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetDefaultVoiceSlotId(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetDefaultVoiceSlotId(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetDefaultVoiceSimId(MessageParcel &data, MessageParcel &reply);
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
    int32_t OnGetNetworkCapability(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetNetworkCapability(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetSimPhoneNumber(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetSimTeleNumberIdentifier(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetVoiceMailInfor(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetVoiceMailNumber(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetVoiceMailCount(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetVoiceMailCount(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetVoiceCallForwarding(MessageParcel &data, MessageParcel &reply);
    int32_t OnDiallingNumbersGet(MessageParcel &data, MessageParcel &reply);
    int32_t OnAddIccDiallingNumbers(MessageParcel &data, MessageParcel &reply);
    int32_t OnUpdateIccDiallingNumbers(MessageParcel &data, MessageParcel &reply);
    int32_t OnDelIccDiallingNumbers(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetVoiceMailInfo(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetMaxSimCount(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetImsRegStatus(MessageParcel &data, MessageParcel &reply);
    int32_t OnSendEnvelopeCmd(MessageParcel &data, MessageParcel &reply);
    int32_t OnSendTerminalResponseCmd(MessageParcel &data, MessageParcel &reply);
    int32_t OnSendCallSetupRequestResult(MessageParcel &data, MessageParcel &reply);
    int32_t OnHasOperatorPrivileges(MessageParcel &data, MessageParcel &reply);
    int32_t OnSimAuthentication(MessageParcel &data, MessageParcel &reply);
    int32_t OnUnlockSimLock(MessageParcel &data, MessageParcel &reply);
    int32_t OnRegisterImsRegInfoCallback(MessageParcel &data, MessageParcel &reply);
    int32_t OnUnregisterImsRegInfoCallback(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetBasebandVersion(MessageParcel &data, MessageParcel &reply);
    int32_t OnFactoryReset(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetNrSsbIdInfo(MessageParcel &data, MessageParcel &reply);
    int32_t OnIsAllowedInsertApn(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetTargetOpkey(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetOpkeyVersion(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetSimIO(MessageParcel &data, MessageParcel &reply);
#ifdef CORE_SERVICE_SUPPORT_ESIM
    int32_t OnRequestDefaultSmdpAddress(MessageParcel &data, MessageParcel &reply);
    int32_t OnCancelSession(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetProfile(MessageParcel &data, MessageParcel &reply);
    int32_t WriteIccIdDatas(EuiccProfile &eUiccProfile);
#endif

private:
    std::map<uint32_t, CoreServiceFunc> memberFuncMap_;
    std::map<uint32_t, std::string> collieCodeStringMap_ = {
        { uint32_t(CoreServiceInterfaceCode::GET_SIGNAL_INFO_LIST), "GET_SIGNAL_INFO_LIST" },
        { uint32_t(CoreServiceInterfaceCode::GET_NETWORK_STATE), "GET_NETWORK_STATE" },
        { uint32_t(CoreServiceInterfaceCode::REG_IMS_CALLBACK), "REG_IMS_CALLBACK" },
        { uint32_t(CoreServiceInterfaceCode::HAS_SIM_CARD), "HAS_SIM_CARD" },
        { uint32_t(CoreServiceInterfaceCode::GET_MAX_SIM_COUNT), "GET_MAX_SIM_COUNT" },
        { uint32_t(CoreServiceInterfaceCode::GET_SIM_STATE), "GET_SIM_STATE" },
        { uint32_t(CoreServiceInterfaceCode::CHECK_LOCK), "CHECK_LOCK" },
        { uint32_t(CoreServiceInterfaceCode::UNLOCK_PIN), "UNLOCK_PIN" },
        { uint32_t(CoreServiceInterfaceCode::UNLOCK_PUK), "UNLOCK_PUK" },
        { uint32_t(CoreServiceInterfaceCode::GET_ACTIVE_ACCOUNT_INFO_LIST), "GET_ACTIVE_ACCOUNT_INFO_LIST" },
    };
};
} // namespace Telephony
} // namespace OHOS
#endif // BASE_PHONE_SERVICE_STUB_H
