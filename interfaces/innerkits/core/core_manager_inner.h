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
#include "i_sim_file_manager.h"
#include "i_sim_state_manager.h"
#include "i_sim_sms_manager.h"
#include "tel_ril_manager.h"
#include "i_sim_account_manager.h"
#include "i_icc_dialling_numbers_manager.h"
#include "i_stk_manager.h"
#include "observer_handler.h"
#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {
struct ManagerInfo {
    std::shared_ptr<INetworkSearch> networkSearchManager;
    std::shared_ptr<Telephony::TelRilManager> telRilManager;
    std::shared_ptr<Telephony::ISimFileManager> simFileManager;
    std::shared_ptr<Telephony::ISimStateManager> simStateManager;
    std::shared_ptr<Telephony::ISimSmsManager> simSmsManager;
    std::shared_ptr<Telephony::ISimAccountManager> simAccountManager;
    std::shared_ptr<Telephony::IIccDiallingNumbersManager> iccDiallingNumbersManager;
    std::shared_ptr<Telephony::IStkManager> stkManager;
};

class CoreManagerInner {
    DECLARE_DELAYED_REF_SINGLETON(CoreManagerInner)

public:
    void RegisterManager(const ManagerInfo &managerInfo);
    void RegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what, void *obj);
    void UnRegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &observerCallBack, int what);

    void SetRadioState(int fun, int rst, const AppExecFwk::InnerEvent::Pointer &response);
    void GetRadioState(const AppExecFwk::InnerEvent::Pointer &response) const;
    void ShutDown(const AppExecFwk::InnerEvent::Pointer &response);
    void GetRadioCapability(const AppExecFwk::InnerEvent::Pointer &response) const;
    void SetRadioCapability(
        RadioCapabilityInfo &radioCapabilityInfo, const AppExecFwk::InnerEvent::Pointer &response) const;
    bool IsNrSupported();
    NrMode GetNrOptionMode(int32_t slotId);
    FrequencyType GetFrequencyType(int32_t slotId) const;
    NrState GetNrState(int32_t slotId) const;
    void DcPhysicalLinkActiveUpdate(int32_t slotId, bool isActive);
    void Dial(std::string address, int clirMode, const AppExecFwk::InnerEvent::Pointer &result);
    void Reject(const AppExecFwk::InnerEvent::Pointer &result);
    void Hangup(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &result);
    void Answer(const AppExecFwk::InnerEvent::Pointer &result);
    void GetCallList(const AppExecFwk::InnerEvent::Pointer &result) const;
    void HoldCall(const AppExecFwk::InnerEvent::Pointer &result);
    void UnHoldCall(const AppExecFwk::InnerEvent::Pointer &result);
    void SwitchCall(const AppExecFwk::InnerEvent::Pointer &result);
    void CombineConference(int32_t callType, const AppExecFwk::InnerEvent::Pointer &result);
    void SeparateConference(int32_t callIndex, int32_t callType, const AppExecFwk::InnerEvent::Pointer &result);
    void CallSupplement(int32_t type, const AppExecFwk::InnerEvent::Pointer &result);
    void GetClip(const AppExecFwk::InnerEvent::Pointer &result) const;
    void SetClip(int32_t action, const AppExecFwk::InnerEvent::Pointer &result);
    void GetClir(const AppExecFwk::InnerEvent::Pointer &result) const;
    void SetClir(int32_t action, const AppExecFwk::InnerEvent::Pointer &result);
    void SetCallWaiting(int32_t activate, const AppExecFwk::InnerEvent::Pointer &result);
    void SetCallTransferInfo(int32_t reason, int32_t mode, std::string number, int32_t classx,
        const AppExecFwk::InnerEvent::Pointer &result);
    void GetCallTransferInfo(int32_t reason, const AppExecFwk::InnerEvent::Pointer &result) const;
    void GetCallWaiting(const AppExecFwk::InnerEvent::Pointer &result) const;
    void GetCallRestriction(std::string fac, const AppExecFwk::InnerEvent::Pointer &result) const;
    void SetCallRestriction(
        std::string &fac, int32_t mode, std::string &password, const AppExecFwk::InnerEvent::Pointer &result);
    /* PDP start */
    int32_t SetInitApnInfo(
        ITelRilManager::CellularDataProfile dataProfile, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t ActivatePdpContext(int32_t radioTechnology, ITelRilManager::CellularDataProfile dataProfile,
        bool isRoaming, bool allowRoaming, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t DeactivatePdpContext(int32_t cid, int32_t reason, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetPdpContextList(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetLinkBandwidthInfo(const int32_t cid, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t SetLinkBandwidthReportingRule(
        LinkBandwidthRule linkBandwidth, const AppExecFwk::InnerEvent::Pointer &response);
    /* PDP end */
    void StopDTMF(int32_t index, const AppExecFwk::InnerEvent::Pointer &result);
    void StartDTMF(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result);
    void SendDTMF(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result);
    void SendDTMF(const std::string &sDTMFCode, int32_t index, int32_t switchOn, int32_t switchOff,
        const AppExecFwk::InnerEvent::Pointer &result);

    void GetImsRegStatus(const AppExecFwk::InnerEvent::Pointer &response) const;
    void GetSignalStrength(const AppExecFwk::InnerEvent::Pointer &response) const;
    void GetCsRegStatus(const AppExecFwk::InnerEvent::Pointer &response) const;
    void GetPsRegStatus(const AppExecFwk::InnerEvent::Pointer &response) const;

    int32_t GetPsRadioTech(int32_t slotId) const;
    int32_t GetCsRadioTech(int32_t slotId) const;
    int32_t GetPsRegState(int32_t slotId) const;
    int32_t GetCsRegState(int32_t slotId) const;
    int32_t GetPsRoamingState(int32_t slotId) const;
    bool SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
        const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
        const sptr<INetworkSearchCallback> &callback);
    std::vector<sptr<SignalInformation>> GetSignalInfoList(int32_t slotId) const;
    std::u16string GetOperatorNumeric(int32_t slotId) const;
    std::u16string GetOperatorName(int32_t slotId) const;
    sptr<NetworkState> GetNetworkStatus(int32_t slotId) const;
    bool SetRadioState(bool isOn, int32_t rst, const sptr<INetworkSearchCallback> &callback);
    int32_t GetRadioState() const;
    bool GetRadioState(const sptr<INetworkSearchCallback> &callback) const;
    std::u16string GetIsoCountryCodeForNetwork(int32_t slotId) const;
    std::u16string GetImei(int32_t slotId) const;
    std::u16string GetMeid(int32_t slotId) const;
    std::u16string GetUniqueDeviceId(int32_t slotId) const;
    PhoneType GetPhoneType() const;
    sptr<CellLocation> GetCellLocation(int32_t slotId) const;
    bool GetNetworkSearchInformation(int32_t slotId, const sptr<INetworkSearchCallback> &callback) const;
    bool GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback) const;
    bool SetPsAttachStatus(int32_t slotId, int32_t psAttachStatus, const sptr<INetworkSearchCallback> &callback);
    int32_t ObtainSpnCondition(bool roaming, std::string operatorNum);
    std::u16string GetSpn(int32_t slotId);
    bool SetVoiceMailInfo(int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber);
    bool GetImsRegStatus() const;
    std::vector<sptr<CellInformation>> GetCellInfoList(int32_t slotId);
    bool SendUpdateCellLocationRequest();
    void GetOperatorInfo(const AppExecFwk::InnerEvent::Pointer &response) const;
    void GetCellInfoList(const AppExecFwk::InnerEvent::Pointer &response);
    void GetCurrentCellInfo(const AppExecFwk::InnerEvent::Pointer &response);

    void SendGsmSms(std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response);
    void SendCdmaSms(std::string pdu, const AppExecFwk::InnerEvent::Pointer &response);
    void AddSimMessage(
        int32_t status, std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response);
    void GetSmscAddr(const AppExecFwk::InnerEvent::Pointer &response) const;
    void GetCdmaCBConfig(const AppExecFwk::InnerEvent::Pointer &response);
    void SetSmscAddr(int32_t tosca, std::string address, const AppExecFwk::InnerEvent::Pointer &response);
    void DelSimMessage(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &response);
    void SendSmsMoreMode(std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response);
    void SendSmsAck(bool success, int32_t cause, const AppExecFwk::InnerEvent::Pointer &response);
    void GetCBConfig(const AppExecFwk::InnerEvent::Pointer &result);
    void SetCBConfig(
        int32_t mode, std::string idList, std::string dcsList, const AppExecFwk::InnerEvent::Pointer &response);
    void SetCdmaCBConfig(
        CdmaCBConfigInfoList &cdmaCBConfigInfoList, const AppExecFwk::InnerEvent::Pointer &response);
    void GetNetworkSearchInformation(const AppExecFwk::InnerEvent::Pointer &response) const;
    void GetNetworkSelectionMode(const AppExecFwk::InnerEvent::Pointer &response) const;
    void SetNetworkSelectionMode(
        int32_t automaticFlag, std::string oper, const AppExecFwk::InnerEvent::Pointer &response);
    void AddCdmaSimMessage(int32_t status, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response);
    void DelCdmaSimMessage(int32_t cdmaIndex, const AppExecFwk::InnerEvent::Pointer &response);
    void UpdateCdmaSimMessage(
        int32_t cdmaIndex, int32_t state, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response);

    void TelRilSetParam(int32_t preferredNetworkType, int32_t cdmaSubscription, int32_t instanceId);
    bool GetPreferredNetwork(int32_t slotId, const sptr<INetworkSearchCallback> &callback);
    bool SetPreferredNetwork(int32_t slotId, int32_t networkMode, const sptr<INetworkSearchCallback> &callback);
    void SetPreferredNetworkPara(int32_t preferredNetworkType, const AppExecFwk::InnerEvent::Pointer &response);
    void GetPreferredNetworkPara(const AppExecFwk::InnerEvent::Pointer &response);
    bool InitCellularRadio(bool isFirst);
    std::vector<std::shared_ptr<DiallingNumbersInfo>> QueryIccDiallingNumbers(int slotId, int type);
    bool AddIccDiallingNumbers(int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);
    bool DelIccDiallingNumbers(int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);
    bool UpdateIccDiallingNumbers(int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);
    bool AddSmsToIcc(int status, std::string &pdu, std::string &smsc);
    bool UpdateSmsIcc(int index, int status, std::string &pduData, std::string &smsc);
    bool DelSmsIcc(int index);
    std::vector<std::string> ObtainAllSmsOfIcc();
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
    std::u16string GetShowNumber(int32_t slotId);
    std::u16string GetShowName(int32_t slotId);
    bool GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList);
    bool GetOperatorConfigs(int slotId, OperatorConfig &poc);
    std::u16string GetSimOperatorNumeric(int32_t slotId);
    std::u16string GetISOCountryCodeForSim(int32_t slotId);
    std::u16string GetSimIccId(int32_t slotId);
    std::u16string GetIMSI(int32_t slotId);
    std::u16string GetLocaleFromDefaultSim();
    std::u16string GetSimGid1(int32_t slotId);
    std::u16string GetSimTelephoneNumber(int32_t slotId);
    std::u16string GetSimTeleNumberIdentifier(const int32_t slotId);
    std::u16string GetVoiceMailIdentifier(int32_t slotId);
    std::u16string GetVoiceMailNumber(int32_t slotId);
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
    int32_t GetMaxSimCount();
    bool SendEnvelopeCmd(const std::string &cmd);
    bool SendTerminalResponseCmd(const std::string &cmd);
    bool UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo, LockStatusResponse &response);
    std::shared_ptr<ITelRilManager> GetRilManager() const;

    void GetImsCallList(const AppExecFwk::InnerEvent::Pointer &result) const;
    void SetCallPreferenceMode(int32_t mode, const AppExecFwk::InnerEvent::Pointer &result) const;
    void GetCallPreferenceMode(const AppExecFwk::InnerEvent::Pointer &result) const;
    void SetLteImsSwitchStatus(int32_t active, const AppExecFwk::InnerEvent::Pointer &result) const;
    void GetLteImsSwitchStatus(const AppExecFwk::InnerEvent::Pointer &result) const;
    void SetUssdCusd(const std::string str, const AppExecFwk::InnerEvent::Pointer &result) const;
    void GetUssdCusd(const AppExecFwk::InnerEvent::Pointer &result) const;
    void GetMute(const AppExecFwk::InnerEvent::Pointer &result) const;
    void SetMute(int32_t mute, const AppExecFwk::InnerEvent::Pointer &result) const;
    void GetEmergencyCallList(const AppExecFwk::InnerEvent::Pointer &result) const;
    void GetCallFailReason(const AppExecFwk::InnerEvent::Pointer &response) const;
    bool HasOperatorPrivileges(const int32_t slotId);

private:
    std::shared_ptr<INetworkSearch> networkSearchManager_ = nullptr;
    std::shared_ptr<Telephony::TelRilManager> telRilManager_ = nullptr;
    std::shared_ptr<Telephony::ISimFileManager> simFileManager_ = nullptr;
    std::shared_ptr<Telephony::ISimStateManager> simStateManager_ = nullptr;
    std::shared_ptr<Telephony::ISimSmsManager> simSmsManager_ = nullptr;
    std::shared_ptr<Telephony::ISimAccountManager> simAccountManager_ = nullptr;
    std::shared_ptr<Telephony::IIccDiallingNumbersManager> iccDiallingNumbersManager_ = nullptr;
    std::shared_ptr<Telephony::IStkManager> stkManager_ = nullptr;
};
} // namespace Telephony
} // namespace OHOS
#endif
