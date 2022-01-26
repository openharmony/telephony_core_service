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

#include "core_manager_inner.h"
#include "network_search_manager.h"
#include "sim_manager.h"
#include "network_search_manager.h"
#include "tel_ril_manager.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "telephony_permission.h"

namespace OHOS {
namespace Telephony {
const std::string OHOS_PERMISSION_GET_NETWORK_INFO = "ohos.permission.GET_NETWORK_INFO";
const std::string OHOS_PERMISSION_LOCATION = "ohos.permission.LOCATION";
const std::string OHOS_PERMISSION_SET_TELEPHONY_STATE = "ohos.permission.SET_TELEPHONY_STATE";
const std::string OHOS_PERMISSION_GET_TELEPHONY_STATE = "ohos.permission.GET_TELEPHONY_STATE";
const std::string OHOS_PERMISSION_GET_SIM_INFO = "ohos.permission.GET_SIM_INFO";
const std::string OHOS_PERMISSION_SET_SIM_INFO = "ohos.permission.SET_SIM_INFO";

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

    if (!registerToService_) {
        bool ret = Publish(DelayedSingleton<CoreService>::GetInstance().get());
        if (!ret) {
            TELEPHONY_LOGE("CoreService::Init Publish failed!");
            return;
        }
        registerToService_ = true;
    }

    if (!Init()) {
        TELEPHONY_LOGE("failed to init CoreService");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    TELEPHONY_LOGI("CoreService start success");
}

bool CoreService::Init()
{
    TELEPHONY_LOGI("CoreService::Init");
    telRilManager_ = std::make_shared<TelRilManager>();
    if (telRilManager_ != nullptr) {
        if (!telRilManager_->OnInit()) {
            TELEPHONY_LOGE("TelRilManager init is failed!");
            return false;
        }
    }
    CoreManagerInner::GetInstance().SetTelRilMangerObj(telRilManager_);
    int32_t slotCount = GetMaxSimCount();
    simManager_ = std::make_shared<SimManager>(telRilManager_);
    if (simManager_ != nullptr) {
        simManager_->OnInit(slotCount);
    }
    networkSearchManager_ = std::make_shared<NetworkSearchManager>(telRilManager_, simManager_);
    if (networkSearchManager_ != nullptr) {
        if (!networkSearchManager_->OnInit()) {
            TELEPHONY_LOGE("NetworkSearchManager init is failed!");
            return false;
        }
    }
    simManager_->SetNetworkSearchManager(slotCount, networkSearchManager_);
    CoreManagerInner::GetInstance().OnInit(networkSearchManager_, simManager_, telRilManager_);
    TELEPHONY_LOGI("CoreService::Init success");
    return true;
}

void CoreService::OnStop()
{
    state_ = ServiceRunningState::STATE_NOT_START;
    registerToService_ = false;
    TELEPHONY_LOGI("CoreService Stop success");
}

int32_t CoreService::GetPsRadioTech(int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_NETWORK_INFO)) {
        return TELEPHONY_PERMISSION_ERROR;
    }
    if (networkSearchManager_ == nullptr) {
        return TELEPHONY_ERROR;
    }
    return networkSearchManager_->GetPsRadioTech(slotId);
}

int32_t CoreService::GetCsRadioTech(int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_NETWORK_INFO)) {
        return TELEPHONY_PERMISSION_ERROR;
    }
    if (networkSearchManager_ == nullptr) {
        return TELEPHONY_ERROR;
    }
    return networkSearchManager_->GetCsRadioTech(slotId);
}

bool CoreService::SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
    const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
    const sptr<INetworkSearchCallback> &callback)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_SET_TELEPHONY_STATE)) {
        return TELEPHONY_PERMISSION_ERROR;
    }
    if (networkSearchManager_ == nullptr) {
        return false;
    }
    TELEPHONY_LOGI("CoreService::SetNetworkSelectionMode selectMode:%{public}d", selectMode);
    return networkSearchManager_->SetNetworkSelectionMode(
        slotId, selectMode, networkInformation, resumeSelection, callback);
}

std::vector<sptr<SignalInformation>> CoreService::GetSignalInfoList(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        return std::vector<sptr<SignalInformation>>();
    }
    return networkSearchManager_->GetSignalInfoList(slotId);
}

std::u16string CoreService::GetOperatorNumeric(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        return std::u16string();
    }
    return networkSearchManager_->GetOperatorNumeric(slotId);
}

std::u16string CoreService::GetOperatorName(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        return std::u16string();
    }
    return networkSearchManager_->GetOperatorName(slotId);
}

const sptr<NetworkState> CoreService::GetNetworkState(int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_NETWORK_INFO)) {
        return nullptr;
    }
    if (networkSearchManager_ == nullptr) {
        return nullptr;
    }
    return networkSearchManager_->GetNetworkStatus(slotId);
}

bool CoreService::SetRadioState(int32_t slotId, bool isOn, const sptr<INetworkSearchCallback> &callback)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_SET_TELEPHONY_STATE)) {
        return TELEPHONY_PERMISSION_ERROR;
    }
    if (networkSearchManager_ == nullptr) {
        return false;
    }
    TELEPHONY_LOGI("CoreService::SetRadioState --> slotId:%{public}d, isOn:%{public}d", slotId, isOn);
    return networkSearchManager_->SetRadioState(slotId, isOn, 0, callback);
}

bool CoreService::GetRadioState(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_NETWORK_INFO)) {
        return TELEPHONY_PERMISSION_ERROR;
    }
    if (networkSearchManager_ == nullptr) {
        return false;
    }
    return networkSearchManager_->GetRadioState(slotId, callback);
}

std::u16string CoreService::GetIsoCountryCodeForNetwork(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        return std::u16string();
    }
    return networkSearchManager_->GetIsoCountryCodeForNetwork(slotId);
}

std::u16string CoreService::GetImei(int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_TELEPHONY_STATE)) {
        return std::u16string();
    }
    if (networkSearchManager_ == nullptr) {
        return std::u16string();
    }
    return networkSearchManager_->GetImei(slotId);
}

std::u16string CoreService::GetMeid(int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_TELEPHONY_STATE)) {
        return std::u16string();
    }
    if (networkSearchManager_ == nullptr) {
        return std::u16string();
    }
    return networkSearchManager_->GetMeid(slotId);
}

std::u16string CoreService::GetUniqueDeviceId(int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_TELEPHONY_STATE)) {
        return std::u16string();
    }
    if (networkSearchManager_ == nullptr) {
        return std::u16string();
    }
    return networkSearchManager_->GetUniqueDeviceId(slotId);
}

bool CoreService::IsNrSupported(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        return false;
    }
    return networkSearchManager_->IsNrSupported(slotId);
}

NrMode CoreService::GetNrOptionMode(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        return NrMode::NR_MODE_UNKNOWN;
    }
    return networkSearchManager_->GetNrOptionMode(slotId);
}

bool CoreService::HasSimCard(int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_SIM_INFO)) {
        return false;
    }
    TELEPHONY_LOGI("CoreService::HasSimCard(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        return TELEPHONY_ERROR;
    }
    return simManager_->HasSimCard(slotId);
}

int32_t CoreService::GetSimState(int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_SIM_INFO)) {
        return TELEPHONY_PERMISSION_ERROR;
    }
    TELEPHONY_LOGI("CoreService::GetSimState(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        return TELEPHONY_ERROR;
    }

    return simManager_->GetSimState(slotId);
}

int32_t CoreService::GetCardType(int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_SIM_INFO)) {
        return TELEPHONY_PERMISSION_ERROR;
    }
    TELEPHONY_LOGI("CoreService::GetCardType(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        return TELEPHONY_ERROR;
    }

    return simManager_->GetCardType(slotId);
}

std::u16string CoreService::GetISOCountryCodeForSim(int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_SIM_INFO)) {
        return std::u16string();
    }
    TELEPHONY_LOGI("CoreService::GetISOCountryCodeForSim(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        return std::u16string();
    }

    return simManager_->GetISOCountryCodeForSim(slotId);
}

std::u16string CoreService::GetSimSpn(int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_SIM_INFO)) {
        return std::u16string();
    }
    TELEPHONY_LOGI("CoreService::GetSimSpn(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        return std::u16string();
    }
    return simManager_->GetSimSpn(slotId);
}

std::u16string CoreService::GetSimIccId(int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_SIM_INFO)) {
        return std::u16string();
    }
    TELEPHONY_LOGI("CoreService::GetSimIccId(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        return std::u16string();
    }
    return simManager_->GetSimIccId(slotId);
}

std::u16string CoreService::GetSimOperatorNumeric(int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_SIM_INFO)) {
        return std::u16string();
    }
    TELEPHONY_LOGI("CoreService::GetSimOperatorNumeric(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        return std::u16string();
    }
    return simManager_->GetSimOperatorNumeric(slotId);
}

std::u16string CoreService::GetIMSI(int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_SIM_INFO)) {
        return std::u16string();
    }
    TELEPHONY_LOGI("CoreService::GetIMSI(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        return std::u16string();
    }
    return simManager_->GetIMSI(slotId);
}

bool CoreService::IsSimActive(int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_SIM_INFO)) {
        return false;
    }
    TELEPHONY_LOGI("CoreService::IsSimActive(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        return false;
    }
    return simManager_->IsSimActive(slotId);
}

bool CoreService::GetNetworkSearchInformation(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    if (networkSearchManager_ == nullptr) {
        return TELEPHONY_ERROR;
    }
    return networkSearchManager_->GetNetworkSearchInformation(slotId, callback);
}

bool CoreService::GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_TELEPHONY_STATE)) {
        return TELEPHONY_PERMISSION_ERROR;
    }
    if (networkSearchManager_ == nullptr) {
        return TELEPHONY_ERROR;
    }
    return networkSearchManager_->GetNetworkSelectionMode(slotId, callback);
}

std::u16string CoreService::GetLocaleFromDefaultSim()
{
    int32_t slotId = DEFAULT_SIM_SLOT_ID;
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_SIM_INFO)) {
        return std::u16string();
    }
    TELEPHONY_LOGI("CoreService::GetSimAccountInfo()");
    if (simManager_ == nullptr) {
        return std::u16string();
    }
    return simManager_->GetLocaleFromDefaultSim(slotId);
}

std::u16string CoreService::GetSimGid1(int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_SIM_INFO)) {
        return std::u16string();
    }
    TELEPHONY_LOGI("CoreService::GetSimGid1(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        return std::u16string();
    }
    return simManager_->GetSimGid1(slotId);
}

bool CoreService::GetSimAccountInfo(int32_t slotId, IccAccountInfo &info)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_SIM_INFO)) {
        return false;
    }
    TELEPHONY_LOGI("CoreService::GetSimAccountInfo(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        return false;
    }
    return simManager_->GetSimAccountInfo(slotId, info);
}

bool CoreService::SetDefaultVoiceSlotId(int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_SET_SIM_INFO)) {
        return false;
    }
    TELEPHONY_LOGI("CoreService::SetDefaultVoiceSlotId(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        return false;
    }
    return simManager_->SetDefaultVoiceSlotId(slotId);
}

int32_t CoreService::GetDefaultVoiceSlotId()
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_SIM_INFO)) {
        return TELEPHONY_PERMISSION_ERROR;
    }
    TELEPHONY_LOGI("CoreService::GetDefaultVoiceSlotId()");
    if (simManager_ == nullptr) {
        return TELEPHONY_ERROR;
    }
    return simManager_->GetDefaultVoiceSlotId();
}

bool CoreService::SetPrimarySlotId(int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_SET_SIM_INFO)) {
        return false;
    }
    TELEPHONY_LOGI("CoreService::SetPrimarySlotId(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        return false;
    }
    return simManager_->SetPrimarySlotId(slotId);
}

int32_t CoreService::GetPrimarySlotId()
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_SIM_INFO)) {
        return TELEPHONY_PERMISSION_ERROR;
    }
    TELEPHONY_LOGI("CoreService::GetPrimarySlotId()");
    if (simManager_ == nullptr) {
        return TELEPHONY_ERROR;
    }
    return simManager_->GetPrimarySlotId();
}

bool CoreService::SetShowNumber(int32_t slotId, const std::u16string number)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_SET_SIM_INFO)) {
        return false;
    }
    TELEPHONY_LOGI("CoreService::SetShowNumber(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        return false;
    }
    return simManager_->SetShowNumber(slotId, number);
}

std::u16string CoreService::GetShowNumber(int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_SIM_INFO)) {
        return std::u16string();
    }
    TELEPHONY_LOGI("CoreService::GetShowNumber(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        return std::u16string();
    }
    return simManager_->GetShowNumber(slotId);
}

bool CoreService::SetShowName(int32_t slotId, const std::u16string name)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_SET_SIM_INFO)) {
        return false;
    }
    TELEPHONY_LOGI("CoreService::SetShowName(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        return false;
    }
    return simManager_->SetShowName(slotId, name);
}

std::u16string CoreService::GetShowName(int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_SIM_INFO)) {
        return std::u16string();
    }
    TELEPHONY_LOGI("CoreService::GetShowName(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        return std::u16string();
    }
    return simManager_->GetShowName(slotId);
}

bool CoreService::GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_SIM_INFO)) {
        return false;
    }
    TELEPHONY_LOGI("CoreService::GetActiveSimAccountInfoList");
    if (simManager_ == nullptr) {
        return false;
    }
    return simManager_->GetActiveSimAccountInfoList(iccAccountInfoList);
}

bool CoreService::GetOperatorConfigs(int32_t slotId, OperatorConfig &poc)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_SIM_INFO)) {
        return false;
    }
    TELEPHONY_LOGI("CoreService::GetOperatorConfigs");
    if (simManager_ == nullptr) {
        return false;
    }
    return simManager_->GetOperatorConfigs(slotId, poc);
}

bool CoreService::UnlockPin(const int32_t slotId, std::u16string pin, LockStatusResponse &response)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_SET_SIM_INFO)) {
        return false;
    }
    TELEPHONY_LOGI(
        "CoreService::UnlockPin(), pin = %{public}s, slotId = %{public}d", Str16ToStr8(pin).c_str(), slotId);
    if (simManager_ == nullptr) {
        return false;
    }
    return simManager_->UnlockPin(slotId, Str16ToStr8(pin), response);
}

bool CoreService::UnlockPuk(const int slotId, std::u16string newPin, std::u16string puk, LockStatusResponse &response)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_SET_SIM_INFO)) {
        return false;
    }
    TELEPHONY_LOGI("CoreService::UnlockPuk(), newPin = %{public}s, puk = %{public}s, slotId = %{public}d",
        Str16ToStr8(newPin).c_str(), Str16ToStr8(puk).c_str(), slotId);
    if (simManager_ == nullptr) {
        return false;
    }
    return simManager_->UnlockPuk(slotId, Str16ToStr8(newPin), Str16ToStr8(puk), response);
}

bool CoreService::AlterPin(
    const int slotId, std::u16string newPin, std::u16string oldPin, LockStatusResponse &response)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_SET_SIM_INFO)) {
        return false;
    }
    TELEPHONY_LOGI("CoreService::AlterPin(), newPin = %{public}s, oldPin = %{public}s, slotId = %{public}d",
        Str16ToStr8(newPin).c_str(), Str16ToStr8(oldPin).c_str(), slotId);
    if (simManager_ == nullptr) {
        return false;
    }
    return simManager_->AlterPin(slotId, Str16ToStr8(newPin), Str16ToStr8(oldPin), response);
}

bool CoreService::UnlockPin2(const int32_t slotId, std::u16string pin2, LockStatusResponse &response)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_SET_SIM_INFO)) {
        return false;
    }
    TELEPHONY_LOGI(
        "CoreService::UnlockPin2(), pin2 = %{public}s, slotId = %{public}d", Str16ToStr8(pin2).c_str(), slotId);
    if (simManager_ == nullptr) {
        return false;
    }
    return simManager_->UnlockPin2(slotId, Str16ToStr8(pin2), response);
}

bool CoreService::UnlockPuk2(
    const int slotId, std::u16string newPin2, std::u16string puk2, LockStatusResponse &response)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_SET_SIM_INFO)) {
        return false;
    }
    TELEPHONY_LOGI("CoreService::UnlockPuk2(), newPin2 = %{public}s, puk2 = %{public}s, slotId = %{public}d",
        Str16ToStr8(newPin2).c_str(), Str16ToStr8(puk2).c_str(), slotId);
    if (simManager_ == nullptr) {
        return false;
    }
    return simManager_->UnlockPuk2(slotId, Str16ToStr8(newPin2), Str16ToStr8(puk2), response);
}

bool CoreService::AlterPin2(
    const int slotId, std::u16string newPin2, std::u16string oldPin2, LockStatusResponse &response)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_SET_SIM_INFO)) {
        return false;
    }
    TELEPHONY_LOGI("CoreService::AlterPin2(), newPin2 = %{public}s, oldPin2 = %{public}s, slotId = %{public}d",
        Str16ToStr8(newPin2).c_str(), Str16ToStr8(oldPin2).c_str(), slotId);
    if (simManager_ == nullptr) {
        return false;
    }
    return simManager_->AlterPin2(slotId, Str16ToStr8(newPin2), Str16ToStr8(oldPin2), response);
}

bool CoreService::SetLockState(int32_t slotId, const LockInfo &options, LockStatusResponse &response)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_SET_SIM_INFO)) {
        return false;
    }
    std::u16string strPin = options.password;
    TELEPHONY_LOGI(
        "CoreService::SetLockState(),lockType = %{public}d, pin = %{public}s, lockState = %{public}d, slotId "
        "= "
        "%{public}d",
        options.lockType, Str16ToStr8(strPin).c_str(), options.lockState, slotId);
    if (simManager_ == nullptr) {
        return false;
    }
    return simManager_->SetLockState(slotId, options, response);
}

int32_t CoreService::GetLockState(int32_t slotId, LockType lockType)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_SIM_INFO)) {
        return TELEPHONY_PERMISSION_ERROR;
    }
    TELEPHONY_LOGI("CoreService::GetLockState(), lockType = %{public}d, slotId = %{public}d", lockType, slotId);
    if (simManager_ == nullptr) {
        return TELEPHONY_ERROR;
    }
    return simManager_->GetLockState(slotId, lockType);
}

int32_t CoreService::RefreshSimState(int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_SIM_INFO)) {
        return TELEPHONY_PERMISSION_ERROR;
    }
    TELEPHONY_LOGI("CoreService::RefreshSimState(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        return TELEPHONY_ERROR;
    }
    return simManager_->RefreshSimState(slotId);
}

bool CoreService::SetActiveSim(int32_t slotId, int32_t enable)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_SET_SIM_INFO)) {
        return false;
    }
    TELEPHONY_LOGI("CoreService::SetActiveSim(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        return false;
    }
    return simManager_->SetActiveSim(slotId, enable);
}

bool CoreService::GetPreferredNetwork(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_TELEPHONY_STATE)) {
        return TELEPHONY_PERMISSION_ERROR;
    }
    if (networkSearchManager_ == nullptr) {
        return TELEPHONY_ERROR;
    }
    return networkSearchManager_->GetPreferredNetwork(slotId, callback);
}

bool CoreService::SetPreferredNetwork(
    int32_t slotId, int32_t networkMode, const sptr<INetworkSearchCallback> &callback)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_SET_TELEPHONY_STATE)) {
        return TELEPHONY_PERMISSION_ERROR;
    }
    if (networkSearchManager_ == nullptr) {
        return TELEPHONY_ERROR;
    }
    return networkSearchManager_->SetPreferredNetwork(slotId, networkMode, callback);
}

bool CoreService::SetPsAttachStatus(
    int32_t slotId, int32_t psAttachStatus, const sptr<INetworkSearchCallback> &callback)
{
    if (networkSearchManager_ == nullptr) {
        return TELEPHONY_ERROR;
    }
    return networkSearchManager_->SetPsAttachStatus(slotId, psAttachStatus, callback);
}

std::u16string CoreService::GetSimTelephoneNumber(int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_SIM_INFO)) {
        return std::u16string();
    }
    TELEPHONY_LOGI("CoreService::GetSimTelephoneNumber(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        return std::u16string();
    }
    return simManager_->GetSimTelephoneNumber(slotId);
}

std::u16string CoreService::GetSimTeleNumberIdentifier(const int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_SIM_INFO)) {
        return std::u16string();
    }
    TELEPHONY_LOGI("CoreService::GetSimTeleNumberIdentifier(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        return std::u16string();
    }
    return simManager_->GetSimTeleNumberIdentifier(slotId);
}

std::u16string CoreService::GetVoiceMailIdentifier(int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_SIM_INFO)) {
        return std::u16string();
    }
    TELEPHONY_LOGI("CoreService::GetVoiceMailIdentifier(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        return std::u16string();
    }
    return simManager_->GetVoiceMailIdentifier(slotId);
}

std::u16string CoreService::GetVoiceMailNumber(int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_SIM_INFO)) {
        return std::u16string();
    }
    TELEPHONY_LOGI("CoreService::GetVoiceMailNumber(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        return std::u16string();
    }
    return simManager_->GetVoiceMailNumber(slotId);
}

std::vector<std::shared_ptr<DiallingNumbersInfo>> CoreService::QueryIccDiallingNumbers(int slotId, int type)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_SIM_INFO)) {
        return std::vector<std::shared_ptr<DiallingNumbersInfo>>();
    }
    TELEPHONY_LOGI("CoreService::QueryIccDiallingNumbers");
    if (simManager_ == nullptr) {
        return std::vector<std::shared_ptr<DiallingNumbersInfo>>();
    }
    return simManager_->QueryIccDiallingNumbers(slotId, type);
}

bool CoreService::AddIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_SET_SIM_INFO)) {
        return false;
    }
    TELEPHONY_LOGI("CoreService::AddIccDiallingNumbers");
    if (simManager_ == nullptr) {
        return false;
    }
    return simManager_->AddIccDiallingNumbers(slotId, type, diallingNumber);
}

bool CoreService::DelIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_SET_SIM_INFO)) {
        return false;
    }
    TELEPHONY_LOGI("CoreService::DelIccDiallingNumbers");
    if (simManager_ == nullptr) {
        return false;
    }
    return simManager_->DelIccDiallingNumbers(slotId, type, diallingNumber);
}

bool CoreService::UpdateIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_SET_SIM_INFO)) {
        return false;
    }
    TELEPHONY_LOGI("CoreService::UpdateIccDiallingNumbers");
    if (simManager_ == nullptr) {
        return false;
    }
    return simManager_->UpdateIccDiallingNumbers(slotId, type, diallingNumber);
}

bool CoreService::SetVoiceMailInfo(
    const int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_SET_SIM_INFO)) {
        return false;
    }
    TELEPHONY_LOGI("CoreService::SetVoiceMailInfo(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        return false;
    }
    return simManager_->SetVoiceMailInfo(slotId, mailName, mailNumber);
}

int32_t CoreService::GetMaxSimCount()
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_SIM_INFO)) {
        return TELEPHONY_PERMISSION_ERROR;
    }
    return SIM_SLOT_COUNT;
}

bool CoreService::SendEnvelopeCmd(int32_t slotId, const std::string &cmd)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_SET_SIM_INFO)) {
        return false;
    }
    TELEPHONY_LOGI("CoreService::SendEnvelopeCmd(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        return false;
    }
    return simManager_->SendEnvelopeCmd(slotId, cmd);
}

bool CoreService::SendTerminalResponseCmd(int32_t slotId, const std::string &cmd)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_SET_SIM_INFO)) {
        return false;
    }
    TELEPHONY_LOGI("CoreService::SendTerminalResponseCmd(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        return false;
    }
    return simManager_->SendTerminalResponseCmd(slotId, cmd);
}

bool CoreService::UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo, LockStatusResponse &response)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_SET_SIM_INFO)) {
        return false;
    }
    TELEPHONY_LOGI(
        "CoreService::UnlockSimLock(), lockType = %{public}d, slotId = %{public}d", lockInfo.lockType, slotId);
    if (simManager_ == nullptr) {
        return false;
    }
    return simManager_->UnlockSimLock(slotId, lockInfo, response);
}

bool CoreService::GetImsRegStatus(int32_t slotId)
{
    TELEPHONY_LOGI("CoreService::GetImsRegStatus --> slotId:%{public}d", slotId);
    if (networkSearchManager_ == nullptr) {
        return TELEPHONY_ERROR;
    }
    return networkSearchManager_->GetImsRegStatus(slotId);
}

std::vector<sptr<CellInformation>> CoreService::GetCellInfoList(int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_LOCATION)) {
        return std::vector<sptr<CellInformation>>();
    }
    if (networkSearchManager_ == nullptr) {
        return std::vector<sptr<CellInformation>>();
    }
    return networkSearchManager_->GetCellInfoList(slotId);
}

bool CoreService::SendUpdateCellLocationRequest(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        return TELEPHONY_ERROR;
    }
    return networkSearchManager_->SendUpdateCellLocationRequest(slotId);
}

bool CoreService::HasOperatorPrivileges(const int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(OHOS_PERMISSION_GET_SIM_INFO)) {
        return false;
    }
    TELEPHONY_LOGI("CoreService::HasOperatorPrivileges(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        return false;
    }
    return simManager_->HasOperatorPrivileges(slotId);
}
} // namespace Telephony
} // namespace OHOS