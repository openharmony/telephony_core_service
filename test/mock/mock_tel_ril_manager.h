#ifndef MOCK_TEL_RIL_MANAGER_H
#define MOCK_TEL_RIL_MANAGER_H
/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "event_runner.h"
#include "tel_ril_network_parcel.h"
#include "tel_ril_sim_parcel.h"
#include "tel_ril_sms_parcel.h"
#include "tel_ril_types.h"
#include "telephony_types.h"
#include <gmock/gmock.h>

namespace OHOS {
namespace Telephony {
class MockTelRilManager : public ITelRilManager {
public:
    MockTelRilManager() = default;
    virtual ~MockTelRilManager() = default;
    MOCK_METHOD0(OnInit, bool(void));
    MOCK_METHOD4(RegisterCoreNotify,
        int32_t(int32_t, const std::shared_ptr<AppExecFwk::EventHandler> &, int32_t, int32_t *));
    MOCK_METHOD3(UnRegisterCoreNotify,
        int32_t(int32_t, const std::shared_ptr<AppExecFwk::EventHandler> &, int32_t));
    MOCK_METHOD1(InitTelExtraModule, int32_t(int32_t));
    MOCK_METHOD4(SetRadioState,
        int32_t(int32_t, int32_t, int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetRadioState, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(ShutDown, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetCallList, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD4(Dial, int32_t(
        int32_t, std::string address, int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(Reject, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(Hangup, int32_t(int32_t, int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(Answer, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(HoldCall, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(UnHoldCall, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(SwitchCall, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(CombineConference, int32_t(
        int32_t, int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD4(SeparateConference, int32_t(
        int32_t, int32_t, int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(CallSupplement, int32_t(int32_t, int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetCallWaiting, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SetCallWaiting, int32_t(
        int32_t, const int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(GetCallTransferInfo, int32_t(
        int32_t, const int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SetCallTransferInfo, int32_t(
        int32_t, const CallTransferParam &, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetClip, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SetClip, int32_t(int32_t, const int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetClir, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SetClir, int32_t(int32_t, const int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(GetCallRestriction, int32_t(
        int32_t, std::string, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SetCallRestriction, int32_t(
        int32_t, const CallRestrictionParam &, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD5(SetBarringPassword, int32_t(int32_t, const char *, const char *,
        const std::string &, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SendDtmf, int32_t(
        int32_t, const DtmfParam &, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD4(SendDtmf, int32_t(
        int32_t, char, int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD4(StartDtmf, int32_t(
        int32_t, char, int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(StopDtmf, int32_t(int32_t, int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SetVoNRSwitch, int32_t(
        int32_t, int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetSignalStrength, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetCsRegStatus, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetPsRegStatus, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetOperatorInfo, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetNeighboringCellInfoList, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetCurrentCellInfo, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetImei, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetImeiSv, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetMeid, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetVoiceRadioTechnology, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetPhysicalChannelConfig, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetBasebandVersion, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SetLocateUpdates, int32_t(
        int32_t, RegNotifyMode, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD4(SendGsmSms, int32_t(
        int32_t, std::string, std::string, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SendCdmaSms, int32_t(int32_t, std::string, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(AddSimMessage, int32_t(
        int32_t, const SimMessageParam &, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(DelSimMessage, int32_t(
        int32_t, int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(UpdateSimMessage, int32_t(
        int32_t, const SimMessageParam &, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetSmscAddr, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetCdmaCBConfig, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD4(SetSmscAddr, int32_t(
        int32_t, int32_t, std::string address, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SetCBConfig, int32_t(
        int32_t, const CBConfigParam &, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SetCdmaCBConfig, int32_t(int32_t, CdmaCBConfigInfoList &,
        const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetCBConfig, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD4(SendSmsMoreMode, int32_t(
        int32_t, std::string, std::string, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD4(SendSmsAck, int32_t(
        int32_t, bool, int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD4(AddCdmaSimMessage, int32_t(
        int32_t, int32_t, std::string, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(DelCdmaSimMessage, int32_t(
        int32_t, int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(UpdateCdmaSimMessage, int32_t(
        int32_t, const CdmaSimMessageParam &, const AppExecFwk::InnerEvent::Pointer &));
    /* PDP start */
    MOCK_METHOD3(SetInitApnInfo, int32_t(
        int32_t, const DataProfile &, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(ActivatePdpContext, int32_t(
        int32_t, const ActivateDataParam &, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD4(DeactivatePdpContext, int32_t(
        int32_t, int32_t, int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetPdpContextList, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(GetLinkBandwidthInfo, int32_t(
        int32_t, const int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SetLinkBandwidthReportingRule, int32_t(
        int32_t, LinkBandwidthRule, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SetDataPermitted, int32_t(
        int32_t, int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetLinkCapability, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(CleanAllConnections, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    /* PDP end */
    MOCK_METHOD2(GetSimStatus, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(GetSimIO, int32_t(
        int32_t, SimIoRequestInfo, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetImsi, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(GetSimLockStatus, int32_t(
        int32_t, std::string, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SetSimLock, int32_t(
        int32_t, const SimLockParam &, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(ChangeSimPassword, int32_t(
        int32_t, const SimPasswordParam &, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(UnlockPin, int32_t(
        int32_t, const std::string &, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD4(UnlockPuk, int32_t(int32_t, const std::string &, const std::string &,
        const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(UnlockPin2, int32_t(
        int32_t, const std::string &, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD4(UnlockPuk2, int32_t(int32_t, const std::string &, const std::string &,
        const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD4(SetActiveSim, int32_t(
        int32_t, int32_t, int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SendTerminalResponseCmd, int32_t(
        int32_t, const std::string &, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SendEnvelopeCmd, int32_t(
        int32_t, const std::string &, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SendCallSetupRequestResult, int32_t(
        int32_t, bool, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(SimStkIsReady, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD4(UnlockSimLock, int32_t(
        int32_t, int32_t, std::string, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetRadioProtocol, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SetRadioProtocol, int32_t(
        int32_t, RadioProtocol, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetNetworkSearchInformation, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetNetworkSelectionMode, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD4(SetNetworkSelectionMode, int32_t(
        int32_t, int32_t, std::string, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SetPreferredNetwork, int32_t(
        int32_t, int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetPreferredNetwork, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SetCallPreferenceMode, int32_t(
        int32_t, const int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetCallPreferenceMode, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SetUssd, int32_t(int32_t, const std::string, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetUssd, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(CloseUnFinishedUssd, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SetMute, int32_t(int32_t, const int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetMute, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetEmergencyCallList, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SetEmergencyCallList, int32_t(
        int32_t, const std::vector<EmergencyCall> &, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetCallFailReason, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD4(SimOpenLogicalChannel, int32_t(int32_t, const std::string &, const int32_t,
        const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SimCloseLogicalChannel, int32_t(
        int32_t, const int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SimTransmitApduLogicalChannel, int32_t(
        int32_t, const ApduSimIORequestInfo &, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SimTransmitApduBasicChannel, int32_t(
        int32_t, const ApduSimIORequestInfo &, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SimAuthentication, int32_t(int32_t, const SimAuthenticationRequestInfo &,
        const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SendSimMatchedOperatorInfo, int32_t(int32_t, const NcfgOperatorInfo &,
        const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SetNotificationFilter, int32_t(
        int32_t, int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD4(SetDeviceState, int32_t(int32_t, int32_t, bool,
        const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD3(SetNrOptionMode, int32_t(int32_t, int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetNrOptionMode, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetRrcConnectionState, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
    MOCK_METHOD2(GetNrSsbId, int32_t(int32_t, const AppExecFwk::InnerEvent::Pointer &));
};
} // namespace Telephony
} // namespace OHOS
#endif // MOCK_TEL_RIL_MANAGER_H