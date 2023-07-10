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

#ifndef IMPL_CORE_MANAGER_INNER_H
#define IMPL_CORE_MANAGER_INNER_H

#include <thread>
#include <unistd.h>

#include "i_network_search.h"
#include "i_sim_manager.h"
#include "i_tel_ril_manager.h"
#include "sim_account_callback.h"
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
    int32_t RegisterSimAccountCallback(const std::string &bundleName, const sptr<SimAccountCallback> &callback);
    int32_t UnregisterSimAccountCallback(const std::string &bundleName);

    /******************** telRilManager start *******************/
    int32_t SetRadioState(
        int32_t slotId, int32_t eventId, int fun, int rst, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t GetRadioState(
        int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t ShutDown(int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
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
    int32_t GetClip(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) const;
    int32_t SetClip(int32_t slotId, int32_t action, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetClir(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) const;
    int32_t SetClir(int32_t slotId, int32_t action, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SetCallWaiting(int32_t slotId, int32_t activate, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SetCallTransferInfo(
        int32_t slotId, const CallTransferParam &callTransfer, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetCallTransferInfo(
        int32_t slotId, const int32_t reason, const AppExecFwk::InnerEvent::Pointer &response) const;
    int32_t GetCallWaiting(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) const;
    int32_t GetCallRestriction(int32_t slotId, std::string fac, const AppExecFwk::InnerEvent::Pointer &response) const;
    int32_t SetCallRestriction(
        int32_t slotId, const CallRestrictionParam &callRestriction, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SetBarringPassword(int32_t slotId, const char *oldPassword,
        const char *newPassword, const std::string &restrictionType, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SetVoNRSwitch(
        int32_t slotId, int32_t state, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    /* PDP start */
    int32_t SetDataPermitted(int32_t slotId, int32_t eventId, int32_t dataPermitted,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);
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
    int32_t GetLinkCapability(
        int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
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

    int32_t GetSignalStrength(
        int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t GetCsRegStatus(
        int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t GetPsRegStatus(
        int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t SetCallPreferenceMode(
        int32_t slotId, int32_t eventId, int32_t mode, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t GetCallPreferenceMode(
        int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t SetUssd(int32_t slotId, int32_t eventId, const std::string str,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t GetUssd(int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t CloseUnFinishedUssd(
        int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t GetMute(int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t SetMute(
        int32_t slotId, int32_t eventId, int32_t mute, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t GetEmergencyCallList(
        int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
    int32_t SetEmergencyCallList(int32_t slotId, int32_t eventId, std::vector<EmergencyCall> &eccVec,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler) const;
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

    /******************** telRilManager end *******************/
    /******************** networkSearchManager start *******************/
    int32_t GetPsRadioTech(int32_t slotId, int32_t &psRadioTech);
    int32_t GetCsRadioTech(int32_t slotId, int32_t &csRadioTech);
    int32_t GetPsRegState(int32_t slotId);
    int32_t GetCsRegState(int32_t slotId);
    int32_t GetPsRoamingState(int32_t slotId);
    bool SetNetworkSelectionMode(int32_t slotId, int32_t selectMode, const sptr<NetworkInformation> &networkInformation,
        bool resumeSelection, const sptr<INetworkSearchCallback> &callback);
    int32_t GetSignalInfoList(int32_t slotId, std::vector<sptr<SignalInformation>> &signals);
    std::u16string GetOperatorNumeric(int32_t slotId);
    int32_t GetOperatorName(int32_t slotId, std::u16string &operatorName);
    int32_t GetNetworkStatus(int32_t slotId, sptr<NetworkState> &networkState);
    int32_t SetRadioState(int32_t slotId, bool isOn, int32_t rst, const sptr<INetworkSearchCallback> &callback);
    int32_t GetRadioState(int32_t slotId);
    int32_t GetRadioState(int32_t slotId, const sptr<INetworkSearchCallback> &callback);
    int32_t GetIsoCountryCodeForNetwork(int32_t slotId, std::u16string &countryCode);
    int32_t GetImei(int32_t slotId, std::u16string &imei);
    int32_t GetMeid(int32_t slotId, std::u16string &meid);
    int32_t GetUniqueDeviceId(int32_t slotId, std::u16string &deviceId);
    PhoneType GetPhoneType(int32_t slotId);
    sptr<CellLocation> GetCellLocation(int32_t slotId);
    int32_t GetNetworkSearchInformation(int32_t slotId, const sptr<INetworkSearchCallback> &callback);
    int32_t GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback);
    int32_t GetImsRegStatus(int32_t slotId, ImsServiceType imsSrvType, ImsRegInfo &info) const;
    int32_t GetCellInfoList(int32_t slotId, std::vector<sptr<CellInformation>> &cellInfo);
    int32_t SendUpdateCellLocationRequest(int32_t slotId);
    int32_t GetPreferredNetwork(int32_t slotId, const sptr<INetworkSearchCallback> &callback);
    int32_t SetPreferredNetwork(int32_t slotId, int32_t networkMode, const sptr<INetworkSearchCallback> &callback);
    int32_t GetAirplaneMode(bool &airplaneMode);
    int32_t UpdateRadioOn(int32_t slotId);

    bool IsNrSupported(int32_t slotId);
    int32_t GetNrOptionMode(int32_t slotId, NrMode &mode);
    FrequencyType GetFrequencyType(int32_t slotId) const;
    NrState GetNrState(int32_t slotId) const;
    void DcPhysicalLinkActiveUpdate(int32_t slotId, bool isActive);
    /******************** networkSearchManager end *******************/
    /******************** simManager start ***************************/
    int32_t ObtainSpnCondition(int32_t slotId, bool roaming, std::string operatorNum);
    int32_t GetSimSpn(int32_t slotId, std::u16string &spn);
    int32_t SetVoiceMailInfo(int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber);
    int32_t HasOperatorPrivileges(const int32_t slotId, bool &hasOperatorPrivileges);
    int32_t SendEnvelopeCmd(int32_t slotId, const std::string &cmd);
    int32_t SendTerminalResponseCmd(int32_t slotId, const std::string &cmd);
    int32_t SendCallSetupRequestResult(int32_t slotId, bool accept);
    int32_t UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo, LockStatusResponse &response);
    int32_t HasSimCard(int32_t slotId, bool &hasSimCard);
    int32_t GetSimState(int32_t slotId, SimState &simState);
    int32_t GetCardType(int32_t slotId, CardType &cardType);
    int32_t UnlockPin(int32_t slotId, const std::string &pin, LockStatusResponse &response);
    int32_t UnlockPuk(int32_t slotId, const std::string &newPin, const std::string &puk, LockStatusResponse &response);
    int32_t AlterPin(
        int32_t slotId, const std::string &newPin, const std::string &oldPin, LockStatusResponse &response);
    int32_t SetLockState(int32_t slotId, const LockInfo &options, LockStatusResponse &response);
    int32_t GetLockState(int32_t slotId, LockType lockType, LockState &lockState);
    int32_t RefreshSimState(int32_t slotId);
    int32_t UnlockPin2(int32_t slotId, const std::string &pin2, LockStatusResponse &response);
    int32_t UnlockPuk2(
        int32_t slotId, const std::string &newPin2, const std::string &puk2, LockStatusResponse &response);
    int32_t AlterPin2(
        int32_t slotId, const std::string &newPin2, const std::string &oldPin2, LockStatusResponse &response);
    int32_t GetShowNumber(int32_t slotId, std::u16string &showNumber);
    int32_t GetShowName(int32_t slotId, std::u16string &showName);
    int32_t GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList);
    int32_t GetOperatorConfigs(int32_t slotId, OperatorConfig &poc);
    int32_t GetSimOperatorNumeric(int32_t slotId, std::u16string &operatorNumeric);
    int32_t GetISOCountryCodeForSim(int32_t slotId, std::u16string &countryCode);
    int32_t GetSimIccId(int32_t slotId, std::u16string &iccId);
    int32_t GetIMSI(int32_t slotId, std::u16string &imsi);
    std::u16string GetLocaleFromDefaultSim(int32_t slotId);
    int32_t GetSlotId(int32_t simId);
    int32_t GetSimId(int32_t slotId);
    int32_t GetSimGid1(int32_t slotId, std::u16string &gid1);
    std::u16string GetSimGid2(int32_t slotId);
    int32_t GetOpName(int32_t slotId, std::u16string &opname);
    int32_t GetOpKeyExt(int32_t slotId, std::u16string &opkeyExt);
    int32_t GetOpKey(std::u16string &opkey);
    int32_t GetOpKey(int32_t slotId, std::u16string &opkey);
    int32_t GetSimTelephoneNumber(int32_t slotId, std::u16string &telephoneNumber);
    std::u16string GetSimTeleNumberIdentifier(const int32_t slotId);
    int32_t GetVoiceMailIdentifier(int32_t slotId, std::u16string &voiceMailIdentifier);
    int32_t GetVoiceMailNumber(int32_t slotId, std::u16string &voiceMailNumber);
    int32_t GetVoiceMailCount(int32_t slotId, int32_t &voiceMailCount);
    int32_t SetVoiceMailCount(int32_t slotId, int32_t voiceMailCount);
    int32_t SetVoiceCallForwarding(int32_t slotId, bool enable, const std::string &number);
    std::u16string GetSimIst(int32_t slotId);
    int32_t QueryIccDiallingNumbers(int slotId, int type, std::vector<std::shared_ptr<DiallingNumbersInfo>> &result);
    int32_t AddIccDiallingNumbers(int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);
    int32_t DelIccDiallingNumbers(int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);
    int32_t UpdateIccDiallingNumbers(int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);
    int32_t AddSmsToIcc(int slotId, int status, std::string &pdu, std::string &smsc);
    int32_t UpdateSmsIcc(int slotId, int index, int status, std::string &pduData, std::string &smsc);
    int32_t DelSmsIcc(int slotId, int index);
    std::vector<std::string> ObtainAllSmsOfIcc(int slotId);
    bool IsSimActive(int32_t slotId);
    int32_t SetActiveSim(int32_t slotId, int32_t enable);
    int32_t GetSimAccountInfo(int32_t slotId, IccAccountInfo &info);
    int32_t SetDefaultVoiceSlotId(int32_t slotId);
    int32_t SetDefaultSmsSlotId(int32_t slotId);
    int32_t SetDefaultCellularDataSlotId(int32_t slotId);
    int32_t SetPrimarySlotId(int32_t slotId);
    int32_t SetShowNumber(int32_t slotId, const std::u16string &number);
    int32_t SetShowName(int32_t slotId, const std::u16string &name);
    int32_t GetDefaultVoiceSlotId();
    int32_t GetDefaultVoiceSimId(int32_t &simId);
    int32_t GetDefaultSmsSlotId();
    int32_t GetDefaultSmsSimId(int32_t &simId);
    int32_t GetDefaultCellularDataSlotId();
    int32_t GetDefaultCellularDataSimId(int32_t &simId);
    int32_t GetPrimarySlotId(int32_t &slotId);
    int32_t SaveImsSwitch(int32_t slotId, int32_t imsSwitchValue);
    int32_t QueryImsSwitch(int32_t slotId, int32_t &imsSwitchValue);
    int32_t GetDsdsMode(int32_t &dsdsMode);
    int32_t SetDsdsMode(int32_t dsdsMode);
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
