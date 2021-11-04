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

#ifndef BASE_PHONE_SERVICE_H
#define BASE_PHONE_SERVICE_H

#include "core_service_stub.h"
#include "if_system_ability_manager.h"
#include "singleton.h"
#include "system_ability.h"

namespace OHOS {
namespace Telephony {
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

    bool SetRadioState(bool isOn, const sptr<INetworkSearchCallback> &callback) override;

    bool GetRadioState(const sptr<INetworkSearchCallback> &callback) override;

    std::u16string GetImei(int32_t slotId) override;

    bool HasSimCard(int32_t slotId) override;

    int32_t GetSimState(int32_t slotId) override;

    std::u16string GetSimOperatorNumeric(int32_t slotId) override;

    std::u16string GetIsoCountryCodeForSim(int32_t slotId) override;

    std::u16string GetSimSpn(int32_t slotId) override;

    std::u16string GetSimIccId(int32_t slotId) override;

    std::u16string GetIMSI(int32_t slotId) override;

    bool IsSimActive(int32_t slotId) override;

    bool GetNetworkSearchResult(int32_t slotId, const sptr<INetworkSearchCallback> &callback) override;

    bool GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback) override;

    std::u16string GetLocaleFromDefaultSim() override;

    std::u16string GetSimGid1(int32_t slotId) override;

    bool SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
        const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
        const sptr<INetworkSearchCallback> &callback) override;

    std::u16string GetIsoCountryCodeForNetwork(int32_t slotId) override;

    bool UnlockPin(std::u16string pin, LockStatusResponse &response, int32_t phoneId) override;

    bool UnlockPuk(
        std::u16string newPin, std::u16string puk, LockStatusResponse &response, int32_t phoneId) override;

    bool AlterPin(
        std::u16string newPin, std::u16string oldPin, LockStatusResponse &response, int32_t phoneId) override;

    bool SetLockState(std::u16string pin, int32_t enable, LockStatusResponse &response, int32_t phoneId) override;

    int32_t GetLockState(int32_t phoneId) override;

    bool GetSimAccountInfo(int32_t subId, IccAccountInfo &info) override;

    bool SetDefaultVoiceSlotId(int32_t subId) override;

    int32_t GetDefaultVoiceSlotId() override;

    int32_t RefreshSimState(int32_t slotId) override;

    std::u16string GetSimTelephoneNumber(int32_t slotId) override;

    std::u16string GetVoiceMailIdentifier(int32_t slotId) override;

    std::u16string GetVoiceMailNumber(int32_t slotId) override;

    std::vector<std::shared_ptr<DiallingNumbersInfo>> QueryIccDiallingNumbers(int slotId, int type) override;

    bool AddIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber) override;

    bool DelIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber) override;

    bool UpdateIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber) override;

    bool SetVoiceMail(const std::u16string &mailName, const std::u16string &mailNumber, int32_t slotId) override;
private:
    bool Init();

private:
    bool registerToService_ = false;
    sptr<ISystemAbilityManager> systemManager_;
    ServiceRunningState state_ = ServiceRunningState::STATE_NOT_START;
};
} // namespace Telephony
} // namespace OHOS
#endif // BASE_PHONE_SERVICE_STUB_H
