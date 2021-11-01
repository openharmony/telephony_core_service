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

#include "system_ability_definition.h"
#include "string_ex.h"

#include "core_manager.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
const bool G_REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<CoreService>::GetInstance().get());

CoreService::CoreService() : SystemAbility(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID, true) {}

CoreService::~CoreService() {}

void CoreService::OnStart()
{
    TELEPHONY_LOGD("CoreService::OnStart start service");

    if (state_ == ServiceRunningState::STATE_RUNNING) {
        TELEPHONY_LOGE("CoreService has already started.");
        return;
    }
    if (!Init()) {
        TELEPHONY_LOGE("failed to init CoreService");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    TELEPHONY_LOGD("CoreService::OnStart start service success.");
}

bool CoreService::Init()
{
    CoreManager::GetInstance().Init();

    TELEPHONY_LOGD("CoreService::Init ready to init......");
    if (!registerToService_) {
        bool ret = Publish(DelayedSingleton<CoreService>::GetInstance().get());
        if (!ret) {
            TELEPHONY_LOGE("CoreService::Init Publish failed!");
            return false;
        }
        registerToService_ = true;
    }
    TELEPHONY_LOGD("CoreService::Init init success.");
    return true;
}

void CoreService::OnStop()
{
    TELEPHONY_LOGD("CoreService::OnStop ready to stop service.");
    state_ = ServiceRunningState::STATE_NOT_START;
    registerToService_ = false;
    TELEPHONY_LOGD("CoreService::OnStop stop service success.");
}

int32_t CoreService::GetPsRadioTech(int32_t slotId)
{
    TELEPHONY_LOGD("CoreService::GetPsRadioTech");
    if (CoreManager::GetInstance().core_.find(slotId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().core_[slotId] == nullptr) {
            return TELEPHONY_ERROR;
        }
        return CoreManager::GetInstance().getCore(slotId)->GetPsRadioTech(slotId);
    } else {
        TELEPHONY_LOGE("CoreService::GetPsRadioTech slotId invalid.");
        return TELEPHONY_ERROR;
    }
}

int32_t CoreService::GetCsRadioTech(int32_t slotId)
{
    TELEPHONY_LOGD("CoreService::GetCsRadioTech");
    if (CoreManager::GetInstance().core_.find(slotId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().core_[slotId] == nullptr) {
            return TELEPHONY_ERROR;
        }
        return CoreManager::GetInstance().getCore(slotId)->GetCsRadioTech(slotId);
    } else {
        TELEPHONY_LOGE("CoreService::GetCsRadioTech slotId invalid.");
        return TELEPHONY_ERROR;
    }
}

bool CoreService::SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
    const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
    const sptr<INetworkSearchCallback> &callback)
{
    TELEPHONY_LOGD("CoreService::SetNetworkSelectionMode");
    if (CoreManager::GetInstance().core_.find(slotId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().core_[slotId] == nullptr) {
            return false;
        }
        TELEPHONY_LOGD("CoreService::SetNetworkSelectionMode selectMode:%{public}d", selectMode);
        return CoreManager::GetInstance().getCore(slotId)->SetNetworkSelectionMode(
            slotId, selectMode, networkInformation, resumeSelection, callback);
    } else {
        TELEPHONY_LOGE("CoreService::SetNetworkSelectionMode slotId invalid.");
        return false;
    }
}

std::vector<sptr<SignalInformation>> CoreService::GetSignalInfoList(int32_t slotId)
{
    TELEPHONY_LOGD("CoreService::GetSignalInfoList");
    if (CoreManager::GetInstance().core_.find(slotId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().core_[slotId] == nullptr) {
            return std::vector<sptr<SignalInformation>>();
        }
        return CoreManager::GetInstance().getCore(slotId)->GetSignalInfoList(slotId);
    } else {
        TELEPHONY_LOGE("CoreService::GetSignalInfoList slotId invalid.");
        return std::vector<sptr<SignalInformation>>();
    }
}

std::u16string CoreService::GetOperatorNumeric(int32_t slotId)
{
    TELEPHONY_LOGD("CoreService::GetOperatorNumeric");
    if (CoreManager::GetInstance().core_.find(slotId) != CoreManager::GetInstance().core_.end()) {
        std::u16string result = CoreManager::GetInstance().getCore(slotId)->GetOperatorNumeric(slotId);
        std::string str = Str16ToStr8(result);
        TELEPHONY_LOGD("CoreService GetOperatorNumeric %{public}s\n", str.c_str());
        return result;
    } else {
        TELEPHONY_LOGE("CoreService::GetOperatorNumeric slotId invalid.");
        return std::u16string();
    }
}

std::u16string CoreService::GetOperatorName(int32_t slotId)
{
    TELEPHONY_LOGD("CoreService::GetOperatorName");
    if (CoreManager::GetInstance().core_.find(slotId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().core_[slotId] == nullptr) {
            return std::u16string();
        }
        return CoreManager::GetInstance().getCore(slotId)->GetOperatorName(slotId);
    } else {
        TELEPHONY_LOGE("CoreService::GetOperatorName slotId invalid.");
        return std::u16string();
    }
}

const sptr<NetworkState> CoreService::GetNetworkState(int32_t slotId)
{
    TELEPHONY_LOGD("CoreService::GetNetworkState");
    if (CoreManager::GetInstance().core_.find(slotId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().core_[slotId] == nullptr) {
            return nullptr;
        }
        return CoreManager::GetInstance().getCore(slotId)->GetNetworkStatus(slotId);
    } else {
        TELEPHONY_LOGE("CoreService::GetNetworkState slotId invalid.");
        return nullptr;
    }
}

bool CoreService::SetRadioState(bool isOn, const sptr<INetworkSearchCallback> &callback)
{
    int32_t slotId = CoreManager::DEFAULT_SLOT_ID;
    TELEPHONY_LOGD("CoreService::SetRadioState --> slotId:%{public}d, isOn:%{public}d", slotId, isOn);
    if (CoreManager::GetInstance().core_.find(slotId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().core_[slotId] == nullptr) {
            return false;
        }
        return CoreManager::GetInstance().getCore(slotId)->SetRadioState(isOn, 0, callback);
    } else {
        TELEPHONY_LOGE("CoreService::SetRadioState slotId invalid.");
        return false;
    }
}

bool CoreService::GetRadioState(const sptr<INetworkSearchCallback> &callback)
{
    int32_t slotId = CoreManager::DEFAULT_SLOT_ID;
    TELEPHONY_LOGD("CoreService::GetRadioState");
    if (CoreManager::GetInstance().core_.find(slotId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().getCore(slotId) == nullptr) {
            return false;
        }
        return static_cast<int32_t>(CoreManager::GetInstance().getCore(slotId)->GetRadioState(callback));
    } else {
        TELEPHONY_LOGE("CoreService::GetRadioState slotId invalid.");
        return false;
    }
}

std::u16string CoreService::GetIsoCountryCodeForNetwork(int32_t slotId)
{
    TELEPHONY_LOGD("CoreService::GetIsoCountryCodeForNetwork");
    if (CoreManager::GetInstance().core_.find(slotId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().core_[slotId] == nullptr) {
            return std::u16string();
        }
        return CoreManager::GetInstance().getCore(slotId)->GetIsoCountryCodeForNetwork(slotId);
    } else {
        TELEPHONY_LOGE("CoreService::GetIsoCountryCodeForNetwork slotId invalid.");
        return std::u16string();
    }
}

std::u16string CoreService::GetImei(int32_t slotId)
{
    TELEPHONY_LOGD("CoreService::GetIMEI");
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return std::u16string();
    }
    return core->GetImei(slotId);
}

bool CoreService::HasSimCard(int32_t slotId)
{
    TELEPHONY_LOGD("CoreService::HasSimCard");
    if (CoreManager::GetInstance().core_.find(slotId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().core_[slotId] == nullptr) {
            return false;
        }
        return CoreManager::GetInstance().core_[slotId]->GetSimStateManager()->HasSimCard(slotId);
    } else {
        TELEPHONY_LOGE("CoreService::HasSimCard slotId invalid.");
        return false;
    }
}

int32_t CoreService::GetSimState(int32_t slotId)
{
    TELEPHONY_LOGD("CoreService::GetSimState");
    if (CoreManager::GetInstance().core_.find(slotId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().core_[slotId] == nullptr) {
            return TELEPHONY_ERROR;
        }
        return CoreManager::GetInstance().core_[slotId]->GetSimStateManager()->GetSimState(slotId);
    } else {
        TELEPHONY_LOGE("CoreService::GetSimState slotId invalid.");
        return TELEPHONY_ERROR;
    }
}

std::u16string CoreService::GetIsoCountryCodeForSim(int32_t slotId)
{
    TELEPHONY_LOGD("CoreService::GetIsoCountryCodeForSim");
    if (CoreManager::GetInstance().core_.find(slotId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().core_[slotId] == nullptr) {
            return std::u16string();
        }
        if (CoreManager::GetInstance().core_[slotId]->GetSimFileManager() != nullptr) {
            return CoreManager::GetInstance().core_[slotId]->GetSimFileManager()->GetIsoCountryCodeForSim(slotId);
        } else {
            TELEPHONY_LOGE("CoreService::GetIsoCountryCodeForSim nullptr simFileManager.");
            return std::u16string();
        }
    } else {
        TELEPHONY_LOGE("CoreService::GetIsoCountryCodeForSim slotId invalid.");
        return std::u16string();
    }
}

std::u16string CoreService::GetSimSpn(int32_t slotId)
{
    TELEPHONY_LOGD("CoreService::GetSimSpn");
    if (CoreManager::GetInstance().core_.find(slotId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().core_[slotId] == nullptr) {
            return std::u16string();
        }
        return CoreManager::GetInstance().core_[slotId]->GetSimFileManager()->GetSimSpn(slotId);
    } else {
        TELEPHONY_LOGE("CoreService::GetSimSpn slotId invalid.");
        return std::u16string();
    }
}

std::u16string CoreService::GetSimIccId(int32_t slotId)
{
    TELEPHONY_LOGD("CoreService::GetSimIccId");
    if (CoreManager::GetInstance().core_.find(slotId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().core_[slotId] == nullptr) {
            return std::u16string();
        }
        return CoreManager::GetInstance().core_[slotId]->GetSimFileManager()->GetSimIccId(slotId);
    } else {
        TELEPHONY_LOGE("CoreService::GetSimIccId slotId invalid.");
        return std::u16string();
    }
}

std::u16string CoreService::GetSimOperatorNumeric(int32_t slotId)
{
    TELEPHONY_LOGD("CoreService::GetSimOperatorNumeric");
    if (CoreManager::GetInstance().core_.find(slotId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().core_[slotId] == nullptr) {
            return std::u16string();
        }
        return CoreManager::GetInstance().core_[slotId]->GetSimFileManager()->GetSimOperatorNumeric(slotId);
    } else {
        TELEPHONY_LOGE("CoreService::GetSimOperatorNumeric slotId invalid.");
        return std::u16string();
    }
}

std::u16string CoreService::GetIMSI(int32_t slotId)
{
    TELEPHONY_LOGD("CoreService::GetIMSI");
    if (CoreManager::GetInstance().core_.find(slotId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().core_[slotId] == nullptr) {
            return std::u16string();
        }
        return CoreManager::GetInstance().core_[slotId]->GetSimFileManager()->GetIMSI(slotId);
    } else {
        TELEPHONY_LOGE("CoreService::GetIMSI slotId invalid.");
        return std::u16string();
    }
}

bool CoreService::IsSimActive(int32_t slotId)
{
    TELEPHONY_LOGD("CoreService::IsSimActive");
    if (CoreManager::GetInstance().core_.find(slotId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().core_[slotId] == nullptr) {
            return false;
        }
        return CoreManager::GetInstance().core_[slotId]->GetSimStateManager()->IsSimActive(slotId);
    } else {
        TELEPHONY_LOGE("CoreService::IsSimActive slotId invalid.");
        return false;
    }
}

bool CoreService::GetNetworkSearchResult(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    TELEPHONY_LOGD("CoreService::GetNetworkSearchResult");
    if (CoreManager::GetInstance().core_.find(slotId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().core_[slotId] == nullptr) {
            return false;
        }
        return CoreManager::GetInstance().getCore(slotId)->GetNetworkSearchResult(slotId, callback);
    } else {
        TELEPHONY_LOGE("CoreService::GetNetworkSearchResult slotId invalid.");
        return false;
    }
}

bool CoreService::GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    TELEPHONY_LOGD("CoreService::GetNetworkSelectionMode");
    if (CoreManager::GetInstance().core_.find(slotId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().core_[slotId] == nullptr) {
            return false;
        }
        return CoreManager::GetInstance().getCore(slotId)->GetNetworkSelectionMode(slotId, callback);
    } else {
        TELEPHONY_LOGE("CoreService::GetNetworkSelectionMode slotId invalid.");
        return false;
    }
}

std::u16string CoreService::GetLocaleFromDefaultSim()
{
    TELEPHONY_LOGD("CoreService::GetLocaleFromDefaultSim");
    int32_t slotId = CoreManager::DEFAULT_SLOT_ID;
    if (CoreManager::GetInstance().core_.find(slotId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().core_[slotId] == nullptr) {
            return std::u16string();
        }
        return CoreManager::GetInstance().core_[slotId]->GetSimFileManager()->GetLocaleFromDefaultSim();
    } else {
        TELEPHONY_LOGE("CoreService::GetLocaleFromDefaultSim slotId invalid.");
        return std::u16string();
    }
}

std::u16string CoreService::GetSimGid1(int32_t slotId)
{
    TELEPHONY_LOGD("CoreService::GetSimGid1");
    if (CoreManager::GetInstance().core_.find(slotId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().core_[slotId] == nullptr) {
            return std::u16string();
        }
        return CoreManager::GetInstance().core_[slotId]->GetSimFileManager()->GetSimGid1(slotId);
    } else {
        TELEPHONY_LOGE("CoreService::GetSimGid1 slotId invalid.");
        return std::u16string();
    }
}

bool CoreService::GetSimAccountInfo(int32_t subId, IccAccountInfo &info)
{
    TELEPHONY_LOGD("CoreService::GetSimAccountInfo");
    int32_t slotId = CoreManager::DEFAULT_SLOT_ID;
    if (CoreManager::GetInstance().core_.find(slotId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().core_[slotId] == nullptr) {
            return false;
        }
        return CoreManager::GetInstance().core_[slotId]->GetSimManager()->GetSimAccountInfo(subId, info);
    } else {
        TELEPHONY_LOGE("CoreService::GetSimAccountInfo subId invalid.");
        return false;
    }
}

bool CoreService::SetDefaultVoiceSlotId(int32_t subId)
{
    TELEPHONY_LOGD("CoreService::SetDefaultVoiceSlotId");
    int32_t slotId = CoreManager::DEFAULT_SLOT_ID;
    if (CoreManager::GetInstance().core_.find(slotId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().core_[slotId] == nullptr) {
            return false;
        }
        return CoreManager::GetInstance().core_[slotId]->GetSimManager()->SetDefaultVoiceSlotId(subId);
    } else {
        TELEPHONY_LOGE("CoreService::SetDefaultVoiceSlotId subId invalid.");
        return false;
    }
}

int32_t CoreService::GetDefaultVoiceSlotId()
{
    TELEPHONY_LOGD("CoreService::GetDefaultVoiceSlotId");
    int32_t slotId = CoreManager::DEFAULT_SLOT_ID;
    if (CoreManager::GetInstance().core_.find(slotId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().core_[slotId] == nullptr) {
            return TELEPHONY_ERROR;
        }
        return CoreManager::GetInstance().core_[slotId]->GetSimManager()->GetDefaultVoiceSlotId();
    } else {
        TELEPHONY_LOGE("CoreService::GetDefaultVoiceSlotId subId invalid.");
        return TELEPHONY_ERROR;
    }
}

bool CoreService::UnlockPin(std::u16string pin, LockStatusResponse &response, int32_t phoneId)
{
    TELEPHONY_LOGD(
        "CoreService::UnlockPin(), pin = %{public}s, phoneId = %{public}d", Str16ToStr8(pin).c_str(), phoneId);
    if (CoreManager::GetInstance().core_.find(phoneId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().core_[phoneId] == nullptr) {
            TELEPHONY_LOGE("CoreService::core_ == nullptr.");
            return false;
        }
        return CoreManager::GetInstance().core_[phoneId]->GetSimStateManager()->UnlockPin(
            Str16ToStr8(pin), response, phoneId);
    } else {
        TELEPHONY_LOGE("CoreService::UnlockPin phoneId invalid.");
        return false;
    }
}

bool CoreService::UnlockPuk(std::u16string newPin, std::u16string puk, LockStatusResponse &response, int phoneId)
{
    TELEPHONY_LOGD("CoreService::UnlockPuk(), newPin = %{public}s, puk = %{public}s, phoneId = %{public}d",
        Str16ToStr8(newPin).c_str(), Str16ToStr8(puk).c_str(), phoneId);
    if (CoreManager::GetInstance().core_.find(phoneId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().core_[phoneId] == nullptr) {
            TELEPHONY_LOGE("CoreService::core_ == nullptr.");
            return false;
        }
        return CoreManager::GetInstance().core_[phoneId]->GetSimStateManager()->UnlockPuk(
            Str16ToStr8(newPin), Str16ToStr8(puk), response, phoneId);
    } else {
        TELEPHONY_LOGE("CoreService::UnlockPuk phoneId invalid.");
        return false;
    }
}

bool CoreService::AlterPin(std::u16string newPin, std::u16string oldPin, LockStatusResponse &response, int phoneId)
{
    TELEPHONY_LOGD("CoreService::AlterPin(), newPin = %{public}s, oldPin = %{public}s, phoneId = %{public}d",
        Str16ToStr8(newPin).c_str(), Str16ToStr8(oldPin).c_str(), phoneId);
    if (CoreManager::GetInstance().core_.find(phoneId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().core_[phoneId] == nullptr) {
            TELEPHONY_LOGE("CoreService::core_ == nullptr.");
            return false;
        }
        return CoreManager::GetInstance().core_[phoneId]->GetSimStateManager()->AlterPin(
            Str16ToStr8(newPin), Str16ToStr8(oldPin), response, phoneId);
    } else {
        TELEPHONY_LOGE("CoreService::AlterPin phoneId invalid.");
        return false;
    }
}

bool CoreService::SetLockState(std::u16string pin, int32_t enable, LockStatusResponse &response, int32_t phoneId)
{
    TELEPHONY_LOGD("CoreService::SetLockState(), pin = %{public}s, enable = %{public}d, phoneId = %{public}d",
        Str16ToStr8(pin).c_str(), enable, phoneId);
    if (CoreManager::GetInstance().core_.find(phoneId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().core_[phoneId] == nullptr) {
            TELEPHONY_LOGE("CoreService::core_ == nullptr.");
            return false;
        }
        return CoreManager::GetInstance().core_[phoneId]->GetSimStateManager()->SetLockState(
            Str16ToStr8(pin), enable, response, phoneId);
    } else {
        TELEPHONY_LOGE("CoreService::SetLockState phoneId invalid.");
        return false;
    }
}

int32_t CoreService::GetLockState(int32_t phoneId)
{
    TELEPHONY_LOGD("CoreService::GetLockState(), phoneId = %{public}d", phoneId);
    if (CoreManager::GetInstance().core_.find(phoneId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().core_[phoneId] == nullptr) {
            TELEPHONY_LOGE("CoreService::core_ == nullptr.");
            return TELEPHONY_ERROR;
        }
        return CoreManager::GetInstance().core_[phoneId]->GetSimStateManager()->GetLockState(phoneId);
    } else {
        TELEPHONY_LOGE("CoreService::GetLockState phoneId invalid.");
        return TELEPHONY_ERROR;
    }
}

int32_t CoreService::RefreshSimState(int32_t phoneId)
{
    TELEPHONY_LOGD("CoreService::RefreshSimState(), phoneId = %{public}d", phoneId);
    if (CoreManager::GetInstance().core_.find(phoneId) != CoreManager::GetInstance().core_.end()) {
        if (CoreManager::GetInstance().core_[phoneId] == nullptr) {
            TELEPHONY_LOGE("CoreService::core_ == nullptr.");
            return TELEPHONY_ERROR;
        }
        return CoreManager::GetInstance().core_[phoneId]->GetSimStateManager()->RefreshSimState(phoneId);
    } else {
        TELEPHONY_LOGE("CoreService::RefreshSimState phoneId invalid.");
        return TELEPHONY_ERROR;
    }
}

std::u16string CoreService::GetSimTelephoneNumber(int32_t slotId)
{
    TELEPHONY_LOGI("CoreService::GetSimTelephoneNumber");
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return std::u16string();
    }
    return core->GetSimTelephoneNumber(slotId);
}

std::u16string CoreService::GetVoiceMailIdentifier(int32_t slotId)
{
    TELEPHONY_LOGI("CoreService::GetVoiceMailIdentifier");
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return std::u16string();
    }
    return core->GetVoiceMailIdentifier(slotId);
}

std::u16string CoreService::GetVoiceMailNumber(int32_t slotId)
{
    TELEPHONY_LOGI("CoreService::GetVoiceMailNumber");
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return std::u16string();
    }
    return core->GetVoiceMailNumber(slotId);
}

std::vector<std::shared_ptr<DiallingNumbersInfo>> CoreService::QueryIccDiallingNumbers(int slotId, int type)
{
    TELEPHONY_LOGI("CoreService::QueryIccDiallingNumbers");
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return std::vector<std::shared_ptr<DiallingNumbersInfo>>();
    }
    return core->QueryIccDiallingNumbers(slotId, type);
}

bool CoreService::AddIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    TELEPHONY_LOGI("CoreService::AddIccDiallingNumbers");
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return false;
    }
    return core->AddIccDiallingNumbers(slotId, type, diallingNumber);
}

bool CoreService::DelIccDiallingNumbers(int slotId, int type, int index)
{
    TELEPHONY_LOGI("CoreService::DelIccDiallingNumbers");
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return false;
    }
    return core->DelIccDiallingNumbers(slotId, type, index);
}

bool CoreService::UpdateIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber, int index)
{
    TELEPHONY_LOGI("CoreService::UpdateIccDiallingNumbers");
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return false;
    }
    return core->UpdateIccDiallingNumbers(slotId, type, diallingNumber, index);
}

bool CoreService::SetVoiceMail(const std::u16string &mailName, const std::u16string &mailNumber, int32_t slotId)
{
    TELEPHONY_LOGI("CoreService::SetVoiceMail");
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId);
    if (core == nullptr) {
        return false;
    }
    return core->SetVoiceMail(mailName, mailNumber, slotId);
}
} // namespace Telephony
} // namespace OHOS
