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

#ifndef I_TEL_RIL_MANAGER_H
#define I_TEL_RIL_MANAGER_H

#include "event_runner.h"
#include "hril_network_parcel.h"
#include "hril_sim_parcel.h"
#include "hril_sms_parcel.h"
#include "hril_types.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {
class ITelRilManager {
public:
    virtual bool OnInit() = 0;
    virtual ~ITelRilManager() = default;

    virtual int32_t RegisterCoreNotify(
        int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler, int32_t what, int32_t *obj) = 0;
    virtual int32_t UnRegisterCoreNotify(
        int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &observerCallBack, int32_t what) = 0;

    virtual int32_t InitTelExtraModule(int32_t slotId) = 0;

    virtual int32_t SetRadioState(
        int32_t slotId, int32_t fun, int32_t rst, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t GetRadioState(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t ShutDown(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t GetCallList(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &result) = 0;

    virtual int32_t Dial(
        int32_t slotId, std::string address, int32_t clirMode, const AppExecFwk::InnerEvent::Pointer &result) = 0;

    virtual int32_t Reject(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &result) = 0;

    virtual int32_t Hangup(int32_t slotId, int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &result) = 0;

    virtual int32_t Answer(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &result) = 0;

    virtual int32_t HoldCall(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &result) = 0;

    virtual int32_t UnHoldCall(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &result) = 0;

    virtual int32_t SwitchCall(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &result) = 0;

    virtual int32_t CombineConference(
        int32_t slotId, int32_t callType, const AppExecFwk::InnerEvent::Pointer &result) = 0;

    virtual int32_t SeparateConference(
        int32_t slotId, int32_t callIndex, int32_t callType, const AppExecFwk::InnerEvent::Pointer &result) = 0;

    virtual int32_t CallSupplement(int32_t slotId, int32_t type, const AppExecFwk::InnerEvent::Pointer &result) = 0;

    virtual int32_t GetCallWaiting(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &result) = 0;

    virtual int32_t SetCallWaiting(
        int32_t slotId, const int32_t activate, const AppExecFwk::InnerEvent::Pointer &result) = 0;

    virtual int32_t GetCallTransferInfo(
        int32_t slotId, const int32_t reason, const AppExecFwk::InnerEvent::Pointer &result) = 0;

    virtual int32_t SetCallTransferInfo(
        int32_t slotId, const CallTransferParam &callTransfer, const AppExecFwk::InnerEvent::Pointer &result) = 0;

    virtual int32_t GetClip(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &result) = 0;

    virtual int32_t SetClip(int32_t slotId, const int32_t action, const AppExecFwk::InnerEvent::Pointer &result) = 0;

    virtual int32_t GetClir(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &result) = 0;

    virtual int32_t SetClir(int32_t slotId, const int32_t action, const AppExecFwk::InnerEvent::Pointer &result) = 0;

    virtual int32_t GetCallRestriction(
        int32_t slotId, std::string fac, const AppExecFwk::InnerEvent::Pointer &result) = 0;

    virtual int32_t SetCallRestriction(
        int32_t slotId, const CallRestrictionParam &callrestriction, const AppExecFwk::InnerEvent::Pointer &result) = 0;

    virtual int32_t SetBarringPassword(int32_t slotId, const char *oldPassword, const char *newPassword,
        const std::string &restrictionType, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t SendDtmf(
        int32_t slotId, const DtmfParam &dtmfParam, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual int32_t SendDtmf(
        int32_t slotId, char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual int32_t StartDtmf(
        int32_t slotId, char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual int32_t StopDtmf(int32_t slotId, int32_t index, const AppExecFwk::InnerEvent::Pointer &result) = 0;

    virtual int32_t SetVoNRSwitch(
        int32_t slotId, int32_t state, const AppExecFwk::InnerEvent::Pointer &result) = 0;

    virtual int32_t GetSignalStrength(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t GetCsRegStatus(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t GetPsRegStatus(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t GetOperatorInfo(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t GetCellInfoList(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t GetCurrentCellInfo(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t GetImei(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t GetImeiSv(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t GetMeid(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t GetVoiceRadioTechnology(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t GetPhysicalChannelConfig(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t GetBasebandVersion(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t SetLocateUpdates(
        int32_t slotId, HRilRegNotifyMode mode, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t SendGsmSms(
        int32_t slotId, std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t SendCdmaSms(int32_t slotId, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t AddSimMessage(
        int32_t slotId, const SimMessageParam &simMessage, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t DelSimMessage(
        int32_t slotId, int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t UpdateSimMessage(
        int32_t slotId, const SimMessageParam &simMessage, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t GetSmscAddr(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t GetCdmaCBConfig(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t SetSmscAddr(
        int32_t slotId, int32_t tosca, std::string address, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t SetCBConfig(
        int32_t slotId, const CBConfigParam &cbConfig, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t SetCdmaCBConfig(int32_t slotId, CdmaCBConfigInfoList &cdmaCBConfigInfoList,
        const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t GetCBConfig(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &result) = 0;

    virtual int32_t SendSmsMoreMode(
        int32_t slotId, std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t SendSmsAck(
        int32_t slotId, bool success, int32_t cause, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t AddCdmaSimMessage(
        int32_t slotId, int32_t status, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t DelCdmaSimMessage(
        int32_t slotId, int32_t cdmaIndex, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t UpdateCdmaSimMessage(
        int32_t slotId, const CdmaSimMessageParam &cdmaSimMsg, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    /* PDP start */
    virtual int32_t SetInitApnInfo(
        int32_t slotId, const DataProfile &dataProfile, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t ActivatePdpContext(
        int32_t slotId, const ActivateDataParam &activeData, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t DeactivatePdpContext(
        int32_t slotId, int32_t cid, int32_t reason, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t GetPdpContextList(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t GetLinkBandwidthInfo(
        int32_t slotId, const int32_t cid, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t SetLinkBandwidthReportingRule(
        int32_t slotId, LinkBandwidthRule linkBandwidth, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t SetDataPermitted(
        int32_t slotId, int32_t dataPermitted, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t GetLinkCapability(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t CleanAllConnections(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    /* PDP end */

    virtual int32_t GetSimStatus(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual int32_t GetSimIO(
        int32_t slotId, SimIoRequestInfo data, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t GetImsi(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual int32_t GetSimLockStatus(
        int32_t slotId, std::string fac, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual int32_t SetSimLock(
        int32_t slotId, const SimLockParam &simLock, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual int32_t ChangeSimPassword(
        int32_t slotId, const SimPasswordParam &simPassword, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual int32_t UnlockPin(
        int32_t slotId, const std::string &pin, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual int32_t UnlockPuk(int32_t slotId, const std::string &puk, const std::string &pin,
        const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual int32_t UnlockPin2(
        int32_t slotId, const std::string &pin2, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual int32_t UnlockPuk2(int32_t slotId, const std::string &puk2, const std::string &pin2,
        const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual int32_t SetActiveSim(
        int32_t slotId, int32_t index, int32_t enable, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual int32_t SendTerminalResponseCmd(
        int32_t slotId, const std::string &strCmd, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t SendEnvelopeCmd(
        int32_t slotId, const std::string &strCmd, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t SendCallSetupRequestResult(
        int32_t slotId, bool accept, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t SimStkIsReady(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t UnlockSimLock(
        int32_t slotId, int32_t lockType, std::string password, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t GetRadioProtocol(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t SetRadioProtocol(
        int32_t slotId, RadioProtocol radioProtocol, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t GetNetworkSearchInformation(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual int32_t GetNetworkSelectionMode(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual int32_t SetNetworkSelectionMode(
        int32_t slotId, int32_t automaticFlag, std::string oper, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual int32_t SetPreferredNetwork(
        int32_t slotId, int32_t preferredNetworkType, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t GetPreferredNetwork(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t SetCallPreferenceMode(
        int32_t slotId, const int32_t mode, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t GetCallPreferenceMode(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t SetUssd(int32_t slotId, const std::string str, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t GetUssd(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t CloseUnFinishedUssd(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t SetMute(int32_t slotId, const int32_t mute, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t GetMute(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t GetEmergencyCallList(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t SetEmergencyCallList(
        int32_t slotId, const std::vector<EmergencyCall> &eccVec, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t GetCallFailReason(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t SimOpenLogicalChannel(int32_t slotId, const std::string &appID, const int32_t p2,
        const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t SimCloseLogicalChannel(
        int32_t slotId, const int32_t channelId, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t SimTransmitApduLogicalChannel(
        int32_t slotId, const ApduSimIORequestInfo &reqInfo, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t SimTransmitApduBasicChannel(
        int32_t slotId, const ApduSimIORequestInfo &reqInfo, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t SimAuthentication(int32_t slotId, const SimAuthenticationRequestInfo &reqInfo,
        const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t SendSimMatchedOperatorInfo(int32_t slotId, const NcfgOperatorInfo &reqInfo,
        const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual int32_t SetNotificationFilter(
        int32_t slotId, int32_t newFilter, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t SetDeviceState(int32_t slotId, int32_t deviceStateType, bool deviceStateOn,
        const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t SetNrOptionMode(int32_t slotId, int32_t mode, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t GetNrOptionMode(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t GetRrcConnectionState(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t GetNrSsbId(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // I_TEL_RIL_MANAGER_H
