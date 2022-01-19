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

#ifndef IMPL_CORE_MANAGER_INNER_H
#define IMPL_CORE_MANAGER_INNER_H

#include <unistd.h>
#include <thread>

#include "singleton.h"

#include "i_network_search.h"
#include "i_sim_manager.h"
#include "i_tel_ril_manager.h"
#include "telephony_errors.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {
class CoreManagerInner final {
public:
    ~CoreManagerInner() = default;
    DISALLOW_COPY_AND_MOVE(CoreManagerInner);
    static CoreManagerInner &GetInstance();
    void OnInit(std::shared_ptr<INetworkSearch> networkSearchManager,
        std::shared_ptr<Telephony::ISimManager> simManager, std::shared_ptr<ITelRilManager> telRilManager);
    void SetTelRilMangerObj(std::shared_ptr<ITelRilManager> telRilManager);
    int32_t RegisterCoreNotify(
        int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what, int32_t *obj);
    int32_t UnRegisterCoreNotify(
        int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &observerCallBack, int what);
    void RegisterCellularDataObject(const sptr<NetworkSearchCallBackBase> &callback);
    void UnRegisterCellularDataObject(const sptr<NetworkSearchCallBackBase> &callback);
    void RegisterCellularCallObject(const sptr<NetworkSearchCallBackBase> &callback);
    void UnRegisterCellularCallObject(const sptr<NetworkSearchCallBackBase> &callback);
    bool IsInitFinished(void);
    bool IsInitFinishedForTelRil(void);
    int32_t GetDefaultSlotId(void);
    int32_t GetMaxSimCount(void);

/******************** telRilManager start *******************/
    int32_t SetRadioState(
        int32_t slotId, int32_t eventId, int fun, int rst, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t GetRadioState(
        int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t ShutDown(int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t GetRadioCapability(
        int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t SetRadioCapability(int32_t slotId, int32_t eventId, RadioCapabilityInfo &radioCapabilityInfo,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t Dial(int32_t slotId, int32_t eventId, std::string address, int clirMode,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t Reject(int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t Hangup(
        int32_t slotId, int32_t eventId, int32_t gsmIndex, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t Answer(int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t GetCallList(
        int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t HoldCall(int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t UnHoldCall(int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t SwitchCall(int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t CombineConference(
        int32_t slotId, int32_t eventId, int32_t callType, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t SeparateConference(int32_t slotId, int32_t eventId, int32_t callIndex, int32_t callType,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t CallSupplement(
        int32_t slotId, int32_t eventId, int32_t type, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t GetClip(int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t SetClip(
        int32_t slotId, int32_t eventId, int32_t action, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t GetClir(int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t SetClir(
        int32_t slotId, int32_t eventId, int32_t action, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t SetCallWaiting(
        int32_t slotId, int32_t eventId, int32_t activate, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t SetCallTransferInfo(int32_t slotId, int32_t eventId, const CallTransferParam &callTransfer,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t GetCallTransferInfo(int32_t slotId, int32_t eventId, const int32_t reason,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t GetCallWaiting(
        int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t GetCallRestriction(int32_t slotId, int32_t eventId, std::string fac,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t SetCallRestriction(int32_t slotId, int32_t eventId, const CallRestrictionParam &callRestriction,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    /* PDP start */
    int32_t SetInitApnInfo(int32_t slotId, int32_t eventId, const DataProfile &dataProfile,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t ActivatePdpContext(int32_t slotId, int32_t eventId, const ActivateDataParam &activateData,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t DeactivatePdpContext(int32_t slotId, int32_t eventId, const DeactivateDataParam &deactivateData,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t GetPdpContextList(
        int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t GetLinkBandwidthInfo(
        int32_t slotId, int32_t eventId, const int32_t cid, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t SetLinkBandwidthReportingRule(int32_t slotId, int32_t eventId, LinkBandwidthRule linkBandwidth,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    /* PDP end */
    int32_t StopDTMF(
        int32_t slotId, int32_t eventId, int32_t index, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t StartDTMF(int32_t slotId, int32_t eventId, char cDTMFCode, int32_t index,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t SendDTMF(int32_t slotId, int32_t eventId, char cDTMFCode, int32_t index,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t SendDTMF(int32_t slotId, int32_t eventId, const DtmfParam &dtmfParam,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    int32_t GetImsRegStatus(
        int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t GetSignalStrength(
        int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t GetCsRegStatus(
        int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t GetPsRegStatus(
        int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t GetImsCallList(
        int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t SetCallPreferenceMode(int32_t slotId, int32_t eventId, int32_t mode,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t GetCallPreferenceMode(
        int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t SetLteImsSwitchStatus(int32_t slotId, int32_t eventId, int32_t active,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t GetLteImsSwitchStatus(
        int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t SetUssdCusd(int32_t slotId, int32_t eventId, const std::string str,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t GetUssdCusd(
        int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t GetMute(int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t SetMute(int32_t slotId, int32_t eventId, int32_t mute,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t GetEmergencyCallList(
        int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t GetCallFailReason(
        int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t GetOperatorInfo(
        int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t GetCellInfoList(int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t GetCurrentCellInfo(
        int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    int32_t SendGsmSms(int32_t slotId, int32_t eventId, GsmSimMessageParam &gsmMessage,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t SendCdmaSms(int32_t slotId, int32_t eventId, std::string pdu, int64_t refId,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t AddSimMessage(int32_t slotId, int32_t eventId, const SimMessageParam &simMessage,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t GetSmscAddr(
        int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t GetCdmaCBConfig(int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t SetSmscAddr(int32_t slotId, int32_t eventId, int32_t tosca, std::string address,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t DelSimMessage(
        int32_t slotId, int32_t eventId, int32_t gsmIndex, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t SendSmsMoreMode(int32_t slotId, int32_t eventId, GsmSimMessageParam &gsmMessage,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t SendSmsAck(int32_t slotId, int32_t eventId, bool success, int32_t cause,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t GetCBConfig(int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t SetCBConfig(int32_t slotId, int32_t eventId, const CBConfigParam &cbConfig,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t SetCdmaCBConfig(int32_t slotId, int32_t eventId, CdmaCBConfigInfoList &cdmaCBConfigInfoList,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t GetNetworkSearchInformation(
        int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t GetNetworkSelectionMode(
        int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t SetNetworkSelectionMode(int32_t slotId, int32_t eventId, int32_t automaticFlag, std::string oper,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t AddCdmaSimMessage(int32_t slotId, int32_t eventId, int32_t status, std::string pdu,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t DelCdmaSimMessage(
        int32_t slotId, int32_t eventId, int32_t cdmaIndex, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t UpdateCdmaSimMessage(int32_t slotId, int32_t eventId, const CdmaSimMessageParam &cdmaSimMsg,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t SetPreferredNetworkPara(int32_t slotId, int32_t eventId, int32_t preferredNetworkType,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t GetPreferredNetworkPara(
        int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    std::vector<std::shared_ptr<DiallingNumbersInfo>> QueryIccDiallingNumbers(int slotId, int type);

/******************** telRilManager end *******************/
/******************** networkSearchManager start *******************/
    int32_t GetPsRadioTech(int32_t slotId);
    int32_t GetCsRadioTech(int32_t slotId);
    int32_t GetPsRegState(int32_t slotId);
    int32_t GetCsRegState(int32_t slotId);
    int32_t GetPsRoamingState(int32_t slotId);
    bool SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
        const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
        const sptr<INetworkSearchCallback> &callback);
    std::vector<sptr<SignalInformation>> GetSignalInfoList(int32_t slotId);
    std::u16string GetOperatorNumeric(int32_t slotId);
    std::u16string GetOperatorName(int32_t slotId);
    sptr<NetworkState> GetNetworkStatus(int32_t slotId);
    bool SetRadioState(int32_t slotId, bool isOn, int32_t rst, const sptr<INetworkSearchCallback> &callback);
    int32_t GetRadioState(int32_t slotId);
    bool GetRadioState(int32_t slotId, const sptr<INetworkSearchCallback> &callback);
    std::u16string GetIsoCountryCodeForNetwork(int32_t slotId);
    std::u16string GetImei(int32_t slotId);
    std::u16string GetMeid(int32_t slotId);
    std::u16string GetUniqueDeviceId(int32_t slotId);
    PhoneType GetPhoneType(int32_t slotId);
    sptr<CellLocation> GetCellLocation(int32_t slotId);
    bool GetNetworkSearchInformation(int32_t slotId, const sptr<INetworkSearchCallback> &callback);
    bool GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback);
    bool SetPsAttachStatus(int32_t slotId, int32_t psAttachStatus, const sptr<INetworkSearchCallback> &callback);
    bool GetImsRegStatus(int32_t slotId) const;
    std::vector<sptr<CellInformation>> GetCellInfoList(int32_t slotId);
    bool SendUpdateCellLocationRequest(int32_t slotId);

    bool GetPreferredNetwork(int32_t slotId, const sptr<INetworkSearchCallback> &callback);
    bool SetPreferredNetwork(int32_t slotId, int32_t networkMode, const sptr<INetworkSearchCallback> &callback);

    bool IsNrSupported(int32_t slotId);
    NrMode GetNrOptionMode(int32_t slotId);
    FrequencyType GetFrequencyType(int32_t slotId) const;
    NrState GetNrState(int32_t slotId) const;
    void DcPhysicalLinkActiveUpdate(int32_t slotId, bool isActive);
/******************** networkSearchManager end *******************/
/******************** simManager start ***************************/
    int32_t ObtainSpnCondition(int32_t slotId, bool roaming, std::string operatorNum);
    std::u16string GetSpn(int32_t slotId);
    bool SetVoiceMailInfo(int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber);
    bool HasOperatorPrivileges(const int32_t slotId);
    bool SendEnvelopeCmd(int32_t slotId, const std::string &cmd);
    bool SendTerminalResponseCmd(int32_t slotId, const std::string &cmd);
    bool UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo, LockStatusResponse &response);
    bool HasSimCard(int32_t slotId);
    int32_t GetSimState(int32_t slotId);
    int32_t GetCardType(int32_t slotId);
    bool UnlockPin(int32_t slotId, std::string pin, LockStatusResponse &response);
    bool UnlockPuk(int32_t slotId, std::string newPin, std::string puk, LockStatusResponse &response);
    bool AlterPin(int32_t slotId, std::string newPin, std::string oldPin, LockStatusResponse &response);
    bool SetLockState(int32_t slotId, const LockInfo &options, LockStatusResponse &response);
    int32_t GetLockState(int32_t slotId, LockType lockType);
    int32_t RefreshSimState(int32_t slotId);
    bool UnlockPin2(int32_t slotId, std::string pin2, LockStatusResponse &response);
    bool UnlockPuk2(int32_t slotId, std::string newPin2, std::string puk2, LockStatusResponse &response);
    bool AlterPin2(int32_t slotId, std::string newPin2, std::string oldPin2, LockStatusResponse &response);
    std::u16string GetShowNumber(int32_t slotId);
    std::u16string GetShowName(int32_t slotId);
    bool GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList);
    bool GetOperatorConfigs(int slotId, OperatorConfig &poc);
    std::u16string GetSimOperatorNumeric(int32_t slotId);
    std::u16string GetISOCountryCodeForSim(int32_t slotId);
    std::u16string GetSimIccId(int32_t slotId);
    std::u16string GetIMSI(int32_t slotId);
    std::u16string GetLocaleFromDefaultSim(int32_t slotId);
    std::u16string GetSimGid1(int32_t slotId);
    std::u16string GetSimTelephoneNumber(int32_t slotId);
    std::u16string GetSimTeleNumberIdentifier(const int32_t slotId);
    std::u16string GetVoiceMailIdentifier(int32_t slotId);
    std::u16string GetVoiceMailNumber(int32_t slotId);
    bool AddIccDiallingNumbers(int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);
    bool DelIccDiallingNumbers(int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);
    bool UpdateIccDiallingNumbers(int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);
    bool AddSmsToIcc(int slotId, int status, std::string &pdu, std::string &smsc);
    bool UpdateSmsIcc(int slotId, int index, int status, std::string &pduData, std::string &smsc);
    bool DelSmsIcc(int slotId, int index);
    std::vector<std::string> ObtainAllSmsOfIcc(int slotId);
    bool IsSimActive(int32_t slotId);
    bool SetActiveSim(int32_t slotId, int32_t enable);
    bool GetSimAccountInfo(int32_t slotId, IccAccountInfo &info);
    bool SetDefaultVoiceSlotId(int32_t slotId);
    bool SetDefaultSmsSlotId(int32_t slotId);
    bool SetDefaultCellularDataSlotId(int32_t slotId);
    bool SetPrimarySlotId(int32_t slotId);
    bool SetShowNumber(int32_t slotId, const std::u16string number);
    bool SetShowName(int32_t slotId, const std::u16string name);
    int32_t GetDefaultVoiceSlotId();
    int32_t GetDefaultSmsSlotId();
    int32_t GetDefaultCellularDataSlotId();
    int32_t GetPrimarySlotId();
/******************** simManager end *****************************/
private:
    CoreManagerInner();

private:
    bool isInitAllObj_ = false;
    std::shared_ptr<INetworkSearch> networkSearchManager_ = nullptr;
    std::shared_ptr<ISimManager> simManager_ = nullptr;
    std::shared_ptr<ITelRilManager> telRilManager_ = nullptr;
};
} // namespace Telephony
} // namespace OHOS
#endif
