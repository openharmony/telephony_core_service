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

#ifndef I_TEL_RIL_MANAGER_H
#define I_TEL_RIL_MANAGER_H

#include "event_runner.h"
#include "hril_types.h"
#include "hril_sim_parcel.h"
#include "hril_sms_parcel.h"
#include "hril_network_parcel.h"

namespace OHOS {
namespace Telephony {
enum ModemPowerState { CORE_SERVICE_POWER_OFF, CORE_SERVICE_POWER_ON, CORE_SERVICE_POWER_NOT_AVAILABLE };

template<typename T>
struct TelRilResponseInfo {
    int32_t slotId;
    int32_t flag;
    int32_t errorNo;
    T object;
};

struct LinkBandwidthRule {
    int32_t rat;
    int32_t delayMs;
    int32_t delayUplinkKbps;
    int32_t delayDownlinkKbps;
    std::vector<int32_t> maximumUplinkKbps;
    std::vector<int32_t> maximumDownlinkKbps;
};

class ITelRilManager {
public:
    class CellularDataProfile {
    public:
        CellularDataProfile(const int profileId, const std::string &apn, const std::string &protocol,
            const int verType, const std::string &userName, const std::string &password,
            const std::string &roamingProtocol)
            : profileId_(profileId), apn_(apn), protocol_(protocol), verType_(verType), userName_(userName),
              password_(password), roamingProtocol_(roamingProtocol)
        {}

        virtual ~CellularDataProfile() = default;

    public:
        int profileId_;
        /** (Access Point Name) a string parameter which is a logical name that is used to select the
         * GGSN or the external packet data network. from 3GPP TS 27.007 10.1 V4.3.0 (2001-12)
         */
        std::string apn_;
        /** (Packet Data Protocol type) a string parameter which specifies the type of packet
         * data protocol from 3GPP TS 27.007 10.1 V4.3.0 (2001-12)
         */
        std::string protocol_;
        int verType_;
        std::string userName_;
        std::string password_;
        std::string roamingProtocol_;
    };

    // RilBaseCommands
    virtual bool OnInit() = 0;
    virtual void InitTelInfo() = 0;

    virtual void RegisterCoreNotify(
        const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what, void *obj) = 0;
    virtual void UnRegisterCoreNotify(
        const std::shared_ptr<AppExecFwk::EventHandler> &observerCallBack, int what) = 0;

    virtual void SetRadioState(int fun, int rst, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetRadioState(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void ShutDown(const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual void Dial(std::string address, int clirMode, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void Reject(const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void Hangup(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void Answer(const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void GetCallList(const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void HoldCall(const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void UnHoldCall(const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void SwitchCall(const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void CombineConference(int32_t callType, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void SeparateConference(
        int32_t callIndex, int32_t callType, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void CallSupplement(int32_t type, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void GetCallWaiting(const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void SetCallWaiting(const int32_t activate, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void GetCallTransferInfo(const int32_t reason, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void SetCallTransferInfo(const int32_t reason, const int32_t mode, std::string number,
        const int32_t classx, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void GetClip(const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void SetClip(const int32_t action, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void GetClir(const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void SetClir(const int32_t action, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void GetCallRestriction(std::string fac, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void SetCallRestriction(
        std::string &fac, int32_t mode, std::string &password, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void SendDtmf(const std::string &sDTMFCode, int32_t index, int32_t switchOn, int32_t switchOff,
        const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void SendDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void StartDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void StopDtmf(int32_t index, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    /* PDP start */
    virtual int32_t SetInitApnInfo(
      CellularDataProfile dataProfile, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t ActivatePdpContext(int32_t radioTechnology, CellularDataProfile dataProfile, bool isRoaming,
        bool allowRoaming, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t DeactivatePdpContext(
        int32_t cid, int32_t reason, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t GetPdpContextList(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t GetLinkBandwidthInfo(
        const int32_t cid, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual int32_t SetLinkBandwidthReportingRule(
        LinkBandwidthRule linkBandwidth, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    /* PDP end */
    virtual void GetSignalStrength(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetCsRegStatus(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetPsRegStatus(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetOperatorInfo(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetCellInfoList(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetCurrentCellInfo(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetImei(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetMeid(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void SetPsAttachStatus(int32_t psAttachStatus, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetPsAttachStatus(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetImsRegStatus(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetVoiceRadioTechnology(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetPhysicalChannelConfig(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void SetLocateUpdates(HRilRegNotifyMode mode, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual void SendGsmSms(
        std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual void SendCdmaSms(std::string pdu, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual void AddSimMessage(
        int32_t status, std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void DelSimMessage(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void UpdateSimMessage(int32_t gsmIndex, int32_t state, std::string smscPdu, std::string pdu,
        const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetSmscAddr(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetCdmaCBConfig(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void SetSmscAddr(
        int32_t tosca, std::string address, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void SetCBConfig(int32_t mode, std::string idList, std::string dcsList,
        const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void SetCdmaCBConfig(
        CdmaCBConfigInfoList &cdmaCBConfigInfoList, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetCBConfig(const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void SendSmsMoreMode(
        std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void SendSmsAck(bool success, int32_t cause, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void AddCdmaSimMessage(int32_t status, std::string pdu,
        const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void DelCdmaSimMessage(int32_t cdmaIndex, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void UpdateCdmaSimMessage(int32_t cdmaIndex, int32_t state, std::string pdu,
        const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual void GetSimStatus(const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void GetSimIO(SimIoRequestInfo data, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetImsi(const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void GetSimLockStatus(std::string fac, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void SetSimLock(
        std::string fac, int32_t mode, std::string passwd, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void ChangeSimPassword(std::string fac, std::string oldPassword, std::string newPassword,
        int32_t passwordLength, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void UnlockPin(std::string pin, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void UnlockPuk(std::string puk, std::string pin, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void GetSimPinInputTimes(const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void UnlockPin2(std::string pin2, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void UnlockPuk2(std::string puk2, std::string pin2, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void GetSimPin2InputTimes(const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void SetActiveSim(int32_t index, int32_t enable, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void UnlockSimLock(int32_t lockType, std::string password,
        const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual void GetNetworkSearchInformation(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetNetworkSelectionMode(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void SetNetworkSelectionMode(
        int32_t automaticFlag, std::string oper, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void SetPreferredNetwork(
        int32_t preferredNetworkType, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetPreferredNetwork(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void TelRilSetParam(int32_t preferredNetworkType, int32_t cdmaSubscription, int32_t instanceId) = 0;
    virtual bool InitCellularRadio(bool isFirst) = 0;
    virtual void GetImsCallList(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void SetCallPreferenceMode(const int32_t mode, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetCallPreferenceMode(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void SetLteImsSwitchStatus(const int32_t active, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetLteImsSwitchStatus(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void SendTerminalResponseCmd(
        const std::string &strCmd, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void SendEnvelopeCmd(const std::string &strCmd, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void StkControllerIsReady(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void StkCmdCallSetup(int32_t flagAccept, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void SetRadioProtocol(SimProtocolRequest data, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void SetUssdCusd(const std::string str, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetUssdCusd(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void SetMute(const int32_t mute, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetMute(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetRadioCapability(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void SetRadioCapability(
        RadioCapabilityInfo &radioCapabilityInfo, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetEmergencyCallList(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetCallFailReason(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void OpenLogicalSimIO(
        const std::string &appID, const int32_t p2, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void CloseLogicalSimIO(const int32_t chanID, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void TransmitApduSimIO(
        ApduSimIORequestInfo reqInfo, const AppExecFwk::InnerEvent::Pointer &response) = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // I_TEL_RIL_MANAGER_H
