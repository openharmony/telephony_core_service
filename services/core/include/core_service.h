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

    int32_t GetPsRadioTech(int32_t slotId) override;

    int32_t GetCsRadioTech(int32_t slotId) override;

    std::vector<sptr<SignalInformation>> GetSignalInfoList(int32_t slotId) override;

    std::u16string GetOperatorNumeric(int32_t slotId) override;

    std::u16string GetOperatorName(int32_t slotId) override;

    const sptr<NetworkState> GetNetworkState(int32_t slotId) override;

    bool SetRadioState(int32_t slotId, bool isOn, const sptr<INetworkSearchCallback> &callback) override;

    bool GetRadioState(int32_t slotId, const sptr<INetworkSearchCallback> &callback) override;

    std::u16string GetImei(int32_t slotId) override;

    std::u16string GetMeid(int32_t slotId) override;

    std::u16string GetUniqueDeviceId(int32_t slotId) override;

    bool IsNrSupported(int32_t slotId) override;

    NrMode GetNrOptionMode(int32_t slotId) override;

    bool HasSimCard(int32_t slotId) override;

    int32_t GetSimState(int32_t slotId) override;

    int32_t GetCardType(int32_t slotId) override;

    std::u16string GetSimOperatorNumeric(int32_t slotId) override;

    std::u16string GetISOCountryCodeForSim(int32_t slotId) override;

    std::u16string GetSimSpn(int32_t slotId) override;

    int32_t GetSimIccId(int32_t slotId, std::u16string &iccId) override;

    int32_t GetIMSI(int32_t slotId, std::u16string &imsi) override;

    bool IsSimActive(int32_t slotId) override;

    int32_t GetSlotId(int32_t simId) override;

    int32_t GetSimId(int32_t slotId) override;

    bool GetNetworkSearchInformation(int32_t slotId, const sptr<INetworkSearchCallback> &callback) override;

    bool GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback) override;

    std::u16string GetLocaleFromDefaultSim() override;

    int32_t GetSimGid1(int32_t slotId, std::u16string &gid1) override;

    std::u16string GetSimGid2(int32_t slotId) override;

    std::u16string GetSimEons(int32_t slotId, const std::string &plmn, int32_t lac, bool longNameRequired) override;

    bool SetNetworkSelectionMode(int32_t slotId, int32_t selectMode, const sptr<NetworkInformation> &networkInformation,
        bool resumeSelection, const sptr<INetworkSearchCallback> &callback) override;

    std::u16string GetIsoCountryCodeForNetwork(int32_t slotId) override;

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

    bool SetPrimarySlotId(int32_t slotId) override;

    int32_t GetPrimarySlotId() override;

    int32_t SetShowNumber(int32_t slotId, const std::u16string &number) override;

    int32_t GetShowNumber(int32_t slotId, std::u16string &showNumber) override;

    int32_t SetShowName(int32_t slotId, const std::u16string &name) override;

    int32_t GetShowName(int32_t slotId, std::u16string &showName) override;

    int32_t RefreshSimState(int32_t slotId) override;

    int32_t SetActiveSim(int32_t slotId, int32_t enable) override;

    bool GetPreferredNetwork(int32_t slotId, const sptr<INetworkSearchCallback> &callback) override;

    bool SetPreferredNetwork(
        int32_t slotId, int32_t networkMode, const sptr<INetworkSearchCallback> &callback) override;

    int32_t GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList) override;

    int32_t GetOperatorConfigs(int32_t slotId, OperatorConfig &poc) override;

    int32_t GetSimTelephoneNumber(int32_t slotId, std::u16string &telephoneNumber) override;

    std::u16string GetSimTeleNumberIdentifier(const int32_t slotId) override;

    int32_t GetVoiceMailIdentifier(int32_t slotId, std::u16string &voiceMailIdentifier) override;

    int32_t GetVoiceMailNumber(int32_t slotId, std::u16string &voiceMailNumber) override;

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

    std::vector<sptr<CellInformation>> GetCellInfoList(int32_t slotId) override;

    bool SendUpdateCellLocationRequest(int32_t slotId) override;

    bool HasOperatorPrivileges(const int32_t slotId) override;

    int32_t SimAuthentication(int32_t slotId, const std::string &aid, const std::string &authData,
        SimAuthenticationResponse &response) override;

    int32_t RegisterImsRegInfoCallback(
        int32_t slotId, ImsServiceType imsSrvType, const sptr<ImsRegInfoCallback> &callback) override;

    int32_t UnregisterImsRegInfoCallback(int32_t slotId, ImsServiceType imsSrvType) override;

    int32_t Dump(std::int32_t fd, const std::vector<std::u16string> &args) override;

    int64_t GetBindTime();

    int64_t GetEndTime();

    int64_t GetSpendTime();

    int32_t GetServiceRunningState();

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
