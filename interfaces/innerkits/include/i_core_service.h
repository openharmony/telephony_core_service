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

#ifndef I_BASE_PHONE_SERVICE_H
#define I_BASE_PHONE_SERVICE_H

#include "cell_information.h"
#include "dialling_numbers_info.h"
#include "i_network_search_callback.h"
#include "ims_reg_info_callback.h"
#include "network_search_result.h"
#include "network_state.h"
#include "nr_ssb_information.h"
#include "operator_config_types.h"
#include "signal_information.h"
#include "sim_state_type.h"

namespace OHOS {
namespace Telephony {
class ICoreService : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.telephony.ICoreService");

public:
    virtual ~ICoreService() = default;
    virtual int32_t GetPsRadioTech(int32_t slotId, int32_t &psRadioTech) = 0;
    virtual int32_t GetCsRadioTech(int32_t slotId, int32_t &csRadioTech) = 0;
    virtual std::u16string GetOperatorNumeric(int32_t slotId) = 0;
    virtual std::string GetResidentNetworkNumeric(int32_t slotId) = 0;
    virtual int32_t GetOperatorName(int32_t slotId, std::u16string &operatorName) = 0;
    virtual int32_t GetSignalInfoList(int32_t slotId, std::vector<sptr<SignalInformation>> &signals) = 0;
    virtual int32_t GetNetworkState(int32_t slotId, sptr<NetworkState> &networkState) = 0;
    virtual int32_t SetRadioState(int32_t slotId, bool isOn, const sptr<INetworkSearchCallback> &callback) = 0;
    virtual int32_t GetRadioState(int32_t slotId, const sptr<INetworkSearchCallback> &callback) = 0;
    virtual int32_t GetImei(int32_t slotId, std::u16string &imei) = 0;
    virtual int32_t GetImeiSv(int32_t slotId, std::u16string &imeiSv) = 0;
    virtual int32_t GetMeid(int32_t slotId, std::u16string &meid) = 0;
    virtual int32_t GetUniqueDeviceId(int32_t slotId, std::u16string &deviceId) = 0;
    virtual bool IsNrSupported(int32_t slotId) = 0;
    virtual int32_t SetNrOptionMode(int32_t slotId, int32_t mode, const sptr<INetworkSearchCallback> &callback) = 0;
    virtual int32_t GetNrOptionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback) = 0;
    virtual int32_t HasSimCard(int32_t slotId, bool &hasSimCard) = 0;
    virtual int32_t GetSimState(int32_t slotId, SimState &simState) = 0;
    virtual int32_t GetDsdsMode(int32_t &dsdsMode) = 0;
    virtual int32_t GetCardType(int32_t slotId, CardType &cardType) = 0;
    virtual int32_t UnlockPin(int32_t slotId, const std::u16string &pin, LockStatusResponse &response) = 0;
    virtual int32_t UnlockPuk(
        int32_t slotId, const std::u16string &newPin, const std::u16string &puk, LockStatusResponse &response) = 0;
    virtual int32_t AlterPin(
        int32_t slotId, const std::u16string &newPin, const std::u16string &oldPin, LockStatusResponse &response) = 0;
    virtual int32_t UnlockPin2(int32_t slotId, const std::u16string &pin2, LockStatusResponse &response) = 0;
    virtual int32_t UnlockPuk2(
        int32_t slotId, const std::u16string &newPin2, const std::u16string &puk2, LockStatusResponse &response) = 0;
    virtual int32_t AlterPin2(
        int32_t slotId, const std::u16string &newPin2, const std::u16string &oldPin2, LockStatusResponse &response) = 0;
    virtual int32_t SetLockState(int32_t slotId, const LockInfo &options, LockStatusResponse &response) = 0;
    virtual int32_t GetLockState(int32_t slotId, LockType lockType, LockState &lockState) = 0;
    virtual int32_t GetSimOperatorNumeric(int32_t slotId, std::u16string &operatorNumeric) = 0;
    virtual int32_t GetISOCountryCodeForSim(int32_t slotId, std::u16string &countryCode) = 0;
    virtual int32_t GetSimSpn(int32_t slotId, std::u16string &spn) = 0;
    virtual int32_t GetSimIccId(int32_t slotId, std::u16string &iccId) = 0;
    virtual int32_t GetIMSI(int32_t slotId, std::u16string &imsi) = 0;
    virtual int32_t IsCTSimCard(int32_t slotId, bool &isCTSimCard) = 0;
    virtual bool IsSimActive(int32_t slotId) = 0;
    virtual int32_t GetSlotId(int32_t simId) = 0;
    virtual int32_t GetSimId(int32_t slotId) = 0;
    virtual int32_t GetNetworkSearchInformation(int32_t slotId, const sptr<INetworkSearchCallback> &callback) = 0;
    virtual int32_t GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback) = 0;
    virtual std::u16string GetLocaleFromDefaultSim() = 0;
    virtual int32_t GetSimGid1(int32_t slotId, std::u16string &gid1) = 0;
    virtual std::u16string GetSimGid2(int32_t slotId) = 0;
    virtual std::u16string GetSimEons(int32_t slotId, const std::string &plmn, int32_t lac, bool longNameRequired) = 0;
    virtual int32_t SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
        const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
        const sptr<INetworkSearchCallback> &callback) = 0;
    virtual int32_t GetIsoCountryCodeForNetwork(int32_t slotId, std::u16string &countryCode) = 0;
    virtual int32_t GetSimAccountInfo(int32_t slotId, IccAccountInfo &info) = 0;
    virtual int32_t SetDefaultVoiceSlotId(int32_t slotId) = 0;
    virtual int32_t GetDefaultVoiceSlotId() = 0;
    virtual int32_t GetDefaultVoiceSimId(int32_t &simId) = 0;
    virtual int32_t SetPrimarySlotId(int32_t slotId) = 0;
    virtual int32_t GetPrimarySlotId(int32_t &slotId) = 0;
    virtual int32_t SetShowNumber(int32_t slotId, const std::u16string &number) = 0;
    virtual int32_t GetShowNumber(int32_t slotId, std::u16string &showNumber) = 0;
    virtual int32_t SetShowName(int32_t slotId, const std::u16string &name) = 0;
    virtual int32_t GetShowName(int32_t slotId, std::u16string &showName) = 0;
    virtual int32_t GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList) = 0;
    virtual int32_t GetOperatorConfigs(int32_t slotId, OperatorConfig &poc) = 0;
    virtual int32_t RefreshSimState(int32_t slotId) = 0;
    virtual int32_t SetActiveSim(int32_t slotId, int32_t enable) = 0;
    virtual int32_t GetPreferredNetwork(int32_t slotId, const sptr<INetworkSearchCallback> &callback) = 0;
    virtual int32_t SetPreferredNetwork(
        int32_t slotId, int32_t networkMode, const sptr<INetworkSearchCallback> &callback) = 0;
    virtual int32_t GetNetworkCapability(
        int32_t slotId, int32_t networkCapabilityType, int32_t &networkCapabilityState) = 0;
    virtual int32_t SetNetworkCapability(
        int32_t slotId, int32_t networkCapabilityType, int32_t networkCapabilityState) = 0;
    virtual int32_t GetSimTelephoneNumber(int32_t slotId, std::u16string &telephoneNumber) = 0;
    virtual std::u16string GetSimTeleNumberIdentifier(const int32_t slotId) = 0;
    virtual int32_t GetVoiceMailIdentifier(int32_t slotId, std::u16string &voiceMailIdentifier) = 0;
    virtual int32_t GetVoiceMailNumber(int32_t slotId, std::u16string &voiceMailNumber) = 0;
    virtual int32_t GetVoiceMailCount(int32_t slotId, int32_t &voiceMailCount) = 0;
    virtual int32_t SetVoiceMailCount(int32_t slotId, int32_t voiceMailCount) = 0;
    virtual int32_t SetVoiceCallForwarding(int32_t slotId, bool enable, const std::string &number) = 0;
    virtual int32_t QueryIccDiallingNumbers(
        int slotId, int type, std::vector<std::shared_ptr<DiallingNumbersInfo>> &result) = 0;
    virtual int32_t AddIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber) = 0;
    virtual int32_t DelIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber) = 0;
    virtual int32_t UpdateIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber) = 0;
    virtual int32_t SetVoiceMailInfo(
        const int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber) = 0;
    virtual int32_t GetImsRegStatus(int32_t slotId, ImsServiceType imsSrvType, ImsRegInfo &info) = 0;
    virtual int32_t GetMaxSimCount() = 0;
    virtual int32_t GetOpKey(int32_t slotId, std::u16string &opkey) = 0;
    virtual int32_t GetOpKeyExt(int32_t slotId, std::u16string &opkeyExt) = 0;
    virtual int32_t GetOpName(int32_t slotId, std::u16string &opname) = 0;
    virtual int32_t SendEnvelopeCmd(int32_t slotId, const std::string &cmd) = 0;
    virtual int32_t SendTerminalResponseCmd(int32_t slotId, const std::string &cmd) = 0;
    virtual int32_t SendCallSetupRequestResult(int32_t slotId, bool accept) = 0;
    virtual int32_t UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo, LockStatusResponse &response) = 0;
    virtual int32_t GetCellInfoList(int32_t slotId, std::vector<sptr<CellInformation>> &cellInfo) = 0;
    virtual int32_t SendUpdateCellLocationRequest(int32_t slotId) = 0;
    virtual int32_t HasOperatorPrivileges(const int32_t slotId, bool &hasOperatorPrivileges) = 0;
    virtual int32_t SimAuthentication(
        int32_t slotId, AuthType authType, const std::string &authData, SimAuthenticationResponse &response) = 0;
    virtual int32_t RegisterImsRegInfoCallback(
        int32_t slotId, ImsServiceType imsSrvType, const sptr<ImsRegInfoCallback> &callback) = 0;
    virtual int32_t UnregisterImsRegInfoCallback(int32_t slotId, ImsServiceType imsSrvType) = 0;
    virtual int32_t GetBasebandVersion(int32_t slotId, std::string &version) = 0;
    virtual int32_t FactoryReset(int32_t slotId) = 0;
    virtual int32_t GetNrSsbIdInfo(int32_t slotId, const std::shared_ptr<NrSsbInformation> &nrSsbInformation) = 0;
    virtual bool IsAllowedInsertApn(std::string &value) = 0;
    virtual int32_t GetTargetOpkey(int32_t slotId, std::u16string &opkey) = 0;
    virtual int32_t GetOpkeyVersion(std::string &versionInfo) = 0;
    virtual int32_t GetSimIO(int32_t slotId, int32_t command,
        int32_t fileId, const std::string &data, const std::string &path, SimAuthenticationResponse &response) = 0;
#ifdef CORE_SERVICE_SUPPORT_ESIM
    virtual int32_t RetrieveNotificationList(
        int32_t slotId, int32_t portIndex, Event events, EuiccNotificationList &notificationList) = 0;
    virtual int32_t RetrieveNotification(
        int32_t slotId, int32_t portIndex, int32_t seqNumber, EuiccNotification &notification) = 0;
    virtual int32_t RemoveNotificationFromList(
        int32_t slotId, int32_t portIndex, int32_t seqNumber, ResultState &enumResult) = 0;
#endif

protected:
    const int32_t ERROR = -1;
    const int32_t MIN_STRING_LE = 0;
    const int32_t MAX_STRING_LE = 36;
    const int32_t MAX_VECTOR = 100;
};
} // namespace Telephony
} // namespace OHOS
#endif // I_BASE_PHONE_SERVICE_H
