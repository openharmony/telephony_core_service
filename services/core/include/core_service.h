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

#ifndef BASE_PHONE_SERVICE_H
#define BASE_PHONE_SERVICE_H

#include "core_service_stub.h"
#include "i_network_search.h"
#include "i_sim_manager.h"
#include "i_tel_ril_manager.h"
#include "if_system_ability_manager.h"
#include "singleton.h"
#include "system_ability.h"
#include "tel_ril_manager.h"
#include "tel_ril_sim_parcel.h"

namespace OHOS {
namespace Telephony {
static const int32_t DEFAULT_SLOT_ID = 0;
enum class ServiceRunningState { STATE_NOT_START, STATE_RUNNING };
class CoreService : public SystemAbility, public CoreServiceStub {
    DECLARE_DELAYED_SINGLETON(CoreService)
    DECLARE_SYSTEM_ABILITY(CoreService)

public:
    void OnStart() override;

    void OnStop() override;

    int32_t GetPsRadioTech(int32_t slotId, int32_t &psRadioTech) override;

    int32_t GetCsRadioTech(int32_t slotId, int32_t &csRadioTech) override;

    int32_t GetSignalInfoList(int32_t slotId, std::vector<sptr<SignalInformation>> &signals) override;

    std::u16string GetOperatorNumeric(int32_t slotId) override;

    std::string GetResidentNetworkNumeric(int32_t slotId) override;

    int32_t GetOperatorName(int32_t slotId, std::u16string &operatorName) override;

    int32_t GetNetworkState(int32_t slotId, sptr<NetworkState> &networkState) override;

    int32_t SetRadioState(int32_t slotId, bool isOn, const sptr<INetworkSearchCallback> &callback) override;

    int32_t GetRadioState(int32_t slotId, const sptr<INetworkSearchCallback> &callback) override;

    int32_t GetImei(int32_t slotId, std::u16string &imei) override;

    int32_t GetImeiSv(int32_t slotId, std::u16string &imeiSv) override;

    int32_t GetMeid(int32_t slotId, std::u16string &meid) override;

    int32_t GetUniqueDeviceId(int32_t slotId, std::u16string &deviceId) override;

    bool IsNrSupported(int32_t slotId) override;

    int32_t SetNrOptionMode(int32_t slotId, int32_t mode, const sptr<INetworkSearchCallback> &callback) override;

    int32_t GetNrOptionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback) override;

    int32_t HasSimCard(int32_t slotId, bool &hasSimCard) override;

    int32_t GetSimState(int32_t slotId, SimState &simState) override;

    int32_t GetDsdsMode(int32_t &dsdsMode) override;

    int32_t GetCardType(int32_t slotId, CardType &cardType) override;

    int32_t GetSimOperatorNumeric(int32_t slotId, std::u16string &operatorNumeric) override;

    int32_t GetISOCountryCodeForSim(int32_t slotId, std::u16string &countryCode) override;

    int32_t GetSimSpn(int32_t slotId, std::u16string &spn) override;

    int32_t GetSimIccId(int32_t slotId, std::u16string &iccId) override;

    int32_t GetIMSI(int32_t slotId, std::u16string &imsi) override;

    int32_t IsCTSimCard(int32_t slotId, bool &isCTSimCard) override;

    bool IsSimActive(int32_t slotId) override;

    int32_t GetSlotId(int32_t simId) override;

    int32_t GetSimId(int32_t slotId) override;

    int32_t GetNetworkSearchInformation(int32_t slotId, const sptr<INetworkSearchCallback> &callback) override;

    int32_t GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback) override;

    std::u16string GetLocaleFromDefaultSim() override;

    int32_t GetSimGid1(int32_t slotId, std::u16string &gid1) override;

    std::u16string GetSimGid2(int32_t slotId) override;

    std::u16string GetSimEons(int32_t slotId, const std::string &plmn, int32_t lac, bool longNameRequired) override;

    int32_t SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
        const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
        const sptr<INetworkSearchCallback> &callback) override;

    int32_t GetIsoCountryCodeForNetwork(int32_t slotId, std::u16string &countryCode) override;

    int32_t UnlockPin(int32_t slotId, const std::u16string &pin, LockStatusResponse &response) override;

    int32_t UnlockPuk(
        int32_t slotId, const std::u16string &newPin, const std::u16string &puk, LockStatusResponse &response) override;

    int32_t AlterPin(int32_t slotId, const std::u16string &newPin, const std::u16string &oldPin,
        LockStatusResponse &response) override;

    int32_t UnlockPin2(int32_t slotId, const std::u16string &pin2, LockStatusResponse &response) override;

    int32_t UnlockPuk2(int32_t slotId, const std::u16string &newPin2, const std::u16string &puk2,
        LockStatusResponse &response) override;

    int32_t AlterPin2(int32_t slotId, const std::u16string &newPin2, const std::u16string &oldPin2,
        LockStatusResponse &response) override;

    int32_t SetLockState(int32_t slotId, const LockInfo &options, LockStatusResponse &response) override;

    int32_t GetLockState(int32_t slotId, LockType lockType, LockState &lockState) override;

    int32_t GetSimAccountInfo(int32_t slotId, IccAccountInfo &info) override;

    int32_t SetDefaultVoiceSlotId(int32_t slotId) override;

    int32_t GetDefaultVoiceSlotId() override;

    int32_t GetDefaultVoiceSimId(int32_t &simId) override;

    int32_t SetPrimarySlotId(int32_t slotId) override;

    int32_t GetPrimarySlotId(int32_t &slotId) override;

    int32_t SetShowNumber(int32_t slotId, const std::u16string &number) override;

    int32_t GetShowNumber(int32_t slotId, std::u16string &showNumber) override;

    int32_t SetShowName(int32_t slotId, const std::u16string &name) override;

    int32_t GetShowName(int32_t slotId, std::u16string &showName) override;

    int32_t RefreshSimState(int32_t slotId) override;

    int32_t SetActiveSim(int32_t slotId, int32_t enable) override;

    int32_t GetPreferredNetwork(int32_t slotId, const sptr<INetworkSearchCallback> &callback) override;

    int32_t SetPreferredNetwork(
        int32_t slotId, int32_t networkMode, const sptr<INetworkSearchCallback> &callback) override;

    int32_t GetNetworkCapability(
        int32_t slotId, int32_t networkCapabilityType, int32_t &networkCapabilitytate) override;

    int32_t SetNetworkCapability(int32_t slotId, int32_t networkCapabilityType, int32_t networkCapabilitytate) override;

    int32_t GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList) override;

    int32_t GetOperatorConfigs(int32_t slotId, OperatorConfig &poc) override;

    int32_t GetSimTelephoneNumber(int32_t slotId, std::u16string &telephoneNumber) override;

    std::u16string GetSimTeleNumberIdentifier(const int32_t slotId) override;

    int32_t GetVoiceMailIdentifier(int32_t slotId, std::u16string &voiceMailIdentifier) override;

    int32_t GetVoiceMailNumber(int32_t slotId, std::u16string &voiceMailNumber) override;

    int32_t GetVoiceMailCount(int32_t slotId, int32_t &voiceMailCount) override;

    int32_t SetVoiceMailCount(int32_t slotId, int32_t voiceMailCount) override;

    int32_t SetVoiceCallForwarding(int32_t slotId, bool enable, const std::string &number) override;

    int32_t QueryIccDiallingNumbers(
        int slotId, int type, std::vector<std::shared_ptr<DiallingNumbersInfo>> &result) override;

    int32_t AddIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber) override;

    int32_t DelIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber) override;

    int32_t UpdateIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber) override;

    int32_t SetVoiceMailInfo(
        const int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber) override;

    int32_t GetImsRegStatus(int32_t slotId, ImsServiceType imsSrvType, ImsRegInfo &info) override;

    int32_t GetMaxSimCount() override;

    int32_t GetOpKey(int32_t slotId, std::u16string &opkey) override;

    int32_t GetOpKeyExt(int32_t slotId, std::u16string &opkeyExt) override;

    int32_t GetOpName(int32_t slotId, std::u16string &opname) override;

    int32_t SendEnvelopeCmd(int32_t slotId, const std::string &cmd) override;

    int32_t SendTerminalResponseCmd(int32_t slotId, const std::string &cmd) override;

    int32_t SendCallSetupRequestResult(int32_t slotId, bool accept) override;

    int32_t UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo, LockStatusResponse &response) override;

    int32_t GetCellInfoList(int32_t slotId, std::vector<sptr<CellInformation>> &cellInfo) override;

    int32_t SendUpdateCellLocationRequest(int32_t slotId) override;

    int32_t HasOperatorPrivileges(const int32_t slotId, bool &hasOperatorPrivileges) override;

    int32_t SimAuthentication(
        int32_t slotId, AuthType authType, const std::string &authData, SimAuthenticationResponse &response) override;

    int32_t RegisterImsRegInfoCallback(
        int32_t slotId, ImsServiceType imsSrvType, const sptr<ImsRegInfoCallback> &callback) override;

    int32_t UnregisterImsRegInfoCallback(int32_t slotId, ImsServiceType imsSrvType) override;

    int32_t GetBasebandVersion(int32_t slotId, std::string &version) override;

    int32_t FactoryReset(int32_t slotId) override;

    int32_t Dump(std::int32_t fd, const std::vector<std::u16string> &args) override;

    int64_t GetBindTime();

    int64_t GetEndTime();

    int64_t GetSpendTime();

    int32_t GetServiceRunningState();

    int32_t GetNrSsbIdInfo(int32_t slotId, const std::shared_ptr<NrSsbInformation> &nrSsbInformation) override;

    bool IsAllowedInsertApn(std::string &value) override;

    int32_t GetTargetOpkey(int32_t slotId, std::u16string &opkey) override;

    int32_t GetOpkeyVersion(std::string &versionInfo) override;

    int32_t GetSimIO(int32_t slotId, int32_t command, int32_t fileId,
        const std::string &data, const std::string &path, SimAuthenticationResponse &response) override;

private:
    bool Init();

private:
    int32_t slotId_ = DEFAULT_SLOT_ID;
    bool registerToService_ = false;
    sptr<ISystemAbilityManager> systemManager_ = nullptr;
    ServiceRunningState state_ = ServiceRunningState::STATE_NOT_START;
    std::shared_ptr<Telephony::ISimManager> simManager_ = nullptr;
    std::shared_ptr<INetworkSearch> networkSearchManager_ = nullptr;
    std::shared_ptr<TelRilManager> telRilManager_ = nullptr;
    int64_t spendTime_ = 0;
    int64_t bindTime_ = 0;
    int64_t endTime_ = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // BASE_PHONE_SERVICE_STUB_H
