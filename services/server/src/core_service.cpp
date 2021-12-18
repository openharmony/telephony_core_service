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

#include "core_service.h"

#include "string_ex.h"
#include "system_ability_definition.h"

#include "core_manager.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
namespace {
const int INVALID_VALUE = -1;
}
const bool G_REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<CoreService>::GetInstance().get());

CoreService::CoreService() : SystemAbility(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID, true) {}

CoreService::~CoreService() {}

void CoreService::OnStart()
{
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        TELEPHONY_LOGE("CoreService has already started.");
        return;
    }
    if (!Init()) {
        TELEPHONY_LOGE("failed to init CoreService");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
}

bool CoreService::Init()
{
    if (!registerToService_) {
        bool ret = Publish(DelayedSingleton<CoreService>::GetInstance().get());
        if (!ret) {
            TELEPHONY_LOGE("CoreService::Init Publish failed!");
            return false;
        }
        registerToService_ = true;
    }
    return true;
}

void CoreService::OnStop()
{
    state_ = ServiceRunningState::STATE_NOT_START;
    registerToService_ = false;
}

int32_t CoreService::GetPsRadioTech(int32_t slotId)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return TELEPHONY_ERROR;
    }
    return core->GetPsRadioTech(slotId);
}

int32_t CoreService::GetCsRadioTech(int32_t slotId)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return TELEPHONY_ERROR;
    }
    return core->GetCsRadioTech(slotId);
}

bool CoreService::SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
    const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
    const sptr<INetworkSearchCallback> &callback)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return false;
    }
    TELEPHONY_LOGI("CoreService::SetNetworkSelectionMode selectMode:%{public}d", selectMode);
    return core->SetNetworkSelectionMode(slotId, selectMode, networkInformation, resumeSelection, callback);
}

std::vector<sptr<SignalInformation>> CoreService::GetSignalInfoList(int32_t slotId)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return std::vector<sptr<SignalInformation>>();
    }
    return core->GetSignalInfoList(slotId);
}

std::u16string CoreService::GetOperatorNumeric(int32_t slotId)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return std::u16string();
    }
    return core->GetOperatorNumeric(slotId);
}

std::u16string CoreService::GetOperatorName(int32_t slotId)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return std::u16string();
    }
    return core->GetOperatorName(slotId);
}

const sptr<NetworkState> CoreService::GetNetworkState(int32_t slotId)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return nullptr;
    }
    return core->GetNetworkStatus(slotId);
}

bool CoreService::SetRadioState(bool isOn, const sptr<INetworkSearchCallback> &callback)
{
    int32_t slotId = CoreManager::DEFAULT_SLOT_ID;
    TELEPHONY_LOGI("CoreService::SetRadioState --> slotId:%{public}d, isOn:%{public}d", slotId, isOn);
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return false;
    }
    return core->SetRadioState(isOn, 0, callback);
}

bool CoreService::GetRadioState(const sptr<INetworkSearchCallback> &callback)
{
    int32_t slotId = CoreManager::DEFAULT_SLOT_ID;
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return false;
    }
    return core->GetRadioState(callback);
}

std::u16string CoreService::GetIsoCountryCodeForNetwork(int32_t slotId)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return std::u16string();
    }
    return core->GetIsoCountryCodeForNetwork(slotId);
}

std::u16string CoreService::GetImei(int32_t slotId)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return std::u16string();
    }
    return core->GetImei(slotId);
}

bool CoreService::HasSimCard(int32_t slotId)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return false;
    }
    return core->HasSimCard(slotId);
}

int32_t CoreService::GetSimState(int32_t slotId)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return TELEPHONY_ERROR;
    }

    return core->GetSimState(slotId);
}

std::u16string CoreService::GetISOCountryCodeForSim(int32_t slotId)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return std::u16string();
    }

    return core->GetISOCountryCodeForSim(slotId);
}

std::u16string CoreService::GetSimSpn(int32_t slotId)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return std::u16string();
    }
    return core->GetSpn(slotId);
}

std::u16string CoreService::GetSimIccId(int32_t slotId)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return std::u16string();
    }
    return core->GetSimIccId(slotId);
}

std::u16string CoreService::GetSimOperatorNumeric(int32_t slotId)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return std::u16string();
    }
    return core->GetSimOperatorNumeric(slotId);
}

std::u16string CoreService::GetIMSI(int32_t slotId)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return std::u16string();
    }
    return core->GetIMSI(slotId);
}

bool CoreService::IsSimActive(int32_t slotId)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return false;
    }
    return core->IsSimActive(slotId);
}

bool CoreService::GetNetworkSearchInformation(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return false;
    }
    return core->GetNetworkSearchInformation(slotId, callback);
}

bool CoreService::GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return false;
    }
    return core->GetNetworkSelectionMode(slotId, callback);
}

std::u16string CoreService::GetLocaleFromDefaultSim()
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(CoreManager::DEFAULT_SLOT_ID);
    if (core == nullptr) {
        return std::u16string();
    }
    return core->GetLocaleFromDefaultSim();
}

std::u16string CoreService::GetSimGid1(int32_t slotId)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return std::u16string();
    }
    return core->GetSimGid1(slotId);
}

bool CoreService::GetSimAccountInfo(int32_t slotId, IccAccountInfo &info)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(CoreManager::DEFAULT_SLOT_ID);
    if (core == nullptr) {
        return false;
    }
    return core->GetSimAccountInfo(slotId, info);
}

bool CoreService::SetDefaultVoiceSlotId(int32_t slotId)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(CoreManager::DEFAULT_SLOT_ID);
    if (core == nullptr) {
        return false;
    }
    return core->SetDefaultVoiceSlotId(slotId);
}

int32_t CoreService::GetDefaultVoiceSlotId()
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(CoreManager::DEFAULT_SLOT_ID);
    if (core == nullptr) {
        return INVALID_VALUE;
    }
    return core->GetDefaultVoiceSlotId();
}

bool CoreService::SetShowNumber(int32_t slotId, const std::u16string name)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(CoreManager::DEFAULT_SLOT_ID);
    if (core == nullptr) {
        return false;
    }
    return core->SetShowNumber(slotId, name);
}

std::u16string CoreService::GetShowNumber(int32_t slotId)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(CoreManager::DEFAULT_SLOT_ID);
    if (core == nullptr) {
        return std::u16string();
    }
    return core->GetShowNumber(slotId);
}

bool CoreService::SetShowName(int32_t slotId, const std::u16string name)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(CoreManager::DEFAULT_SLOT_ID);
    if (core == nullptr) {
        return false;
    }
    return core->SetShowName(slotId, name);
}

std::u16string CoreService::GetShowName(int32_t slotId)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(CoreManager::DEFAULT_SLOT_ID);
    if (core == nullptr) {
        return std::u16string();
    }
    return core->GetShowName(slotId);
}

bool CoreService::GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(CoreManager::DEFAULT_SLOT_ID);
    if (core == nullptr) {
        return false;
    }
    return core->GetActiveSimAccountInfoList(iccAccountInfoList);
}

bool CoreService::GetOperatorConfigs(int32_t slotId, OperatorConfig &poc)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(CoreManager::DEFAULT_SLOT_ID);
    if (core == nullptr) {
        return false;
    }
    return core->GetOperatorConfigs(slotId, poc);
}

bool CoreService::UnlockPin(int32_t slotId, std::u16string pin, LockStatusResponse &response)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return false;
    }
    return core->UnlockPin(slotId, Str16ToStr8(pin), response);
}

bool CoreService::UnlockPuk(int slotId, std::u16string newPin, std::u16string puk, LockStatusResponse &response)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return false;
    }
    return core->UnlockPuk(slotId, Str16ToStr8(newPin), Str16ToStr8(puk), response);
}

bool CoreService::AlterPin(int slotId, std::u16string newPin, std::u16string oldPin, LockStatusResponse &response)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return false;
    }
    return core->AlterPin(slotId, Str16ToStr8(newPin), Str16ToStr8(oldPin), response);
}

bool CoreService::UnlockPin2(int32_t slotId, std::u16string pin2, LockStatusResponse &response)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return false;
    }
    return core->UnlockPin2(slotId, Str16ToStr8(pin2), response);
}

bool CoreService::UnlockPuk2(int slotId, std::u16string newPin2, std::u16string puk2, LockStatusResponse &response)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return false;
    }
    return core->UnlockPuk2(slotId, Str16ToStr8(newPin2), Str16ToStr8(puk2), response);
}

bool CoreService::AlterPin2(
    int slotId, std::u16string newPin2, std::u16string oldPin2, LockStatusResponse &response)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return false;
    }
    return core->AlterPin2(slotId, Str16ToStr8(newPin2), Str16ToStr8(oldPin2), response);
}

bool CoreService::SetLockState(int32_t slotId, std::u16string pin, int32_t enable, LockStatusResponse &response)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return false;
    }
    return core->SetLockState(slotId, Str16ToStr8(pin), enable, response);
}

int32_t CoreService::GetLockState(int32_t slotId)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return TELEPHONY_ERROR;
    }
    return core->GetLockState(slotId);
}

int32_t CoreService::RefreshSimState(int32_t slotId)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return TELEPHONY_ERROR;
    }
    return core->RefreshSimState(slotId);
}

bool CoreService::SetActiveSim(const int32_t slotId, int32_t enable)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(CoreManager::DEFAULT_SLOT_ID);
    if (core == nullptr) {
        return false;
    }
    return core->SetActiveSim(slotId, enable);
}

bool CoreService::GetPreferredNetwork(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return false;
    }
    return core->GetPreferredNetwork(slotId, callback);
}

bool CoreService::SetPreferredNetwork(
    int32_t slotId, int32_t networkMode, const sptr<INetworkSearchCallback> &callback)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return false;
    }
    return core->SetPreferredNetwork(slotId, networkMode, callback);
}

bool CoreService::SetPsAttachStatus(
    int32_t slotId, int32_t psAttachStatus, const sptr<INetworkSearchCallback> &callback)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return false;
    }
    return core->SetPsAttachStatus(slotId, psAttachStatus, callback);
}

std::u16string CoreService::GetSimTelephoneNumber(int32_t slotId)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return std::u16string();
    }
    return core->GetSimTelephoneNumber(slotId);
}

std::u16string CoreService::GetVoiceMailIdentifier(int32_t slotId)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return std::u16string();
    }
    return core->GetVoiceMailIdentifier(slotId);
}

std::u16string CoreService::GetVoiceMailNumber(int32_t slotId)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return std::u16string();
    }
    return core->GetVoiceMailNumber(slotId);
}

std::vector<std::shared_ptr<DiallingNumbersInfo>> CoreService::QueryIccDiallingNumbers(int slotId, int type)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return std::vector<std::shared_ptr<DiallingNumbersInfo>>();
    }
    return core->QueryIccDiallingNumbers(slotId, type);
}

bool CoreService::AddIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return false;
    }
    return core->AddIccDiallingNumbers(slotId, type, diallingNumber);
}

bool CoreService::DelIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return false;
    }
    return core->DelIccDiallingNumbers(slotId, type, diallingNumber);
}

bool CoreService::UpdateIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return false;
    }
    return core->UpdateIccDiallingNumbers(slotId, type, diallingNumber);
}

bool CoreService::SetVoiceMailInfo(int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return false;
    }
    return core->SetVoiceMailInfo(slotId, mailName, mailNumber);
}

int32_t CoreService::GetMaxSimCount()
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(CoreManager::DEFAULT_SLOT_ID);
    if (core == nullptr) {
        return INVALID_VALUE;
    }
    return core->GetMaxSimCount();
}

bool CoreService::GetImsRegStatus(int32_t slotId)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return false;
    }
    return core->GetImsRegStatus();
}

std::vector<sptr<CellInformation>> CoreService::GetCellInfoList(int32_t slotId)
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return std::vector<sptr<CellInformation>>();
    }
    return core->GetCellInfoList(slotId);
}

bool CoreService::SendUpdateCellLocationRequest()
{
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(CoreManager::DEFAULT_SLOT_ID);
    if (core == nullptr) {
        return false;
    }
    return core->SendUpdateCellLocationRequest();
}
} // namespace Telephony
} // namespace OHOS
