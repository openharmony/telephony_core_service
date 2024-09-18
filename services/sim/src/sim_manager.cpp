/*
 * Copyright (C) 2021-2024 Huawei Device Co., Ltd.
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

#include "sim_manager.h"

#include "core_service_errors.h"
#include "radio_event.h"
#include "telephony_errors.h"
#include "telephony_ext_wrapper.h"
#include "telephony_permission.h"

namespace OHOS {
namespace Telephony {
SimManager::SimManager(std::shared_ptr<ITelRilManager> telRilManager) : telRilManager_(telRilManager)
{
    TELEPHONY_LOGI("SimManager::SimManager()");
}

SimManager::~SimManager() {}

bool SimManager::OnInit(int32_t slotCount)
{
    TELEPHONY_LOGI("SimManager OnInit, slotCount = %{public}d", slotCount);
    slotCount_ = slotCount;
    InitMultiSimObject();
    InitSingleSimObject();
    TELEPHONY_LOGD("SimManager OnInit success");
    return true;
}

void SimManager::InitMultiSimObject()
{
    // Program memory
    simStateManager_.resize(slotCount_);
    simFileManager_.resize(slotCount_);
    simSmsManager_.resize(slotCount_);
    simAccountManager_.resize(slotCount_);
    iccDiallingNumbersManager_.resize(slotCount_);
    stkManager_.resize(slotCount_);
    // Many card create
    for (int32_t slotId = 0; slotId < slotCount_; slotId++) {
        InitBaseManager(slotId);
        simSmsManager_[slotId] =
            std::make_shared<SimSmsManager>(telRilManager_, simFileManager_[slotId], simStateManager_[slotId]);
        if (simSmsManager_[slotId] != nullptr) {
            simSmsManager_[slotId]->Init(slotId);
        }
        iccDiallingNumbersManager_[slotId] = IccDiallingNumbersManager::CreateInstance(
            std::weak_ptr<SimFileManager>(simFileManager_[slotId]), simStateManager_[slotId]);
        if (iccDiallingNumbersManager_[slotId] != nullptr) {
            iccDiallingNumbersManager_[slotId]->Init();
        }
        stkManager_[slotId] = std::make_shared<StkManager>(telRilManager_, simStateManager_[slotId]);
        if (stkManager_[slotId] != nullptr) {
            stkManager_[slotId]->Init(slotId);
        }
        if (simStateManager_[slotId] != nullptr) {
            simStateManager_[slotId]->RefreshSimState(slotId);
        }
    }
}

int32_t SimManager::InitTelExtraModule(int32_t slotId)
{
    if (slotId != SIM_SLOT_2) {
        return TELEPHONY_ERROR;
    }
    if (simStateManager_.size() == MAX_SLOT_COUNT) {
        TELEPHONY_LOGI("SimManager InitTelExtraModule, slotId = %{public}d, has been inited, return.", slotId);
        return TELEPHONY_SUCCESS;
    }
    // Program memory
    simStateManager_.resize(MAX_SLOT_COUNT);
    simFileManager_.resize(MAX_SLOT_COUNT);
    simAccountManager_.resize(MAX_SLOT_COUNT);
    InitBaseManager(slotId);
    multiSimController_->AddExtraManagers(simStateManager_[slotId], simFileManager_[slotId]);
    multiSimMonitor_->AddExtraManagers(simStateManager_[slotId], simFileManager_[slotId]);
    slotCount_ = MAX_SLOT_COUNT;
    return TELEPHONY_SUCCESS;
}

void SimManager::InitBaseManager(int32_t slotId)
{
    if (slotId < 0 || slotId >= static_cast<int32_t>(simStateManager_.size())) {
        return;
    }
    simStateManager_[slotId] = std::make_shared<SimStateManager>(telRilManager_);
    if (simStateManager_[slotId] != nullptr) {
        simStateManager_[slotId]->Init(slotId);
    }
    simFileManager_[slotId] = SimFileManager::CreateInstance(std::weak_ptr<ITelRilManager>(telRilManager_),
        std::weak_ptr<SimStateManager>(simStateManager_[slotId]));
    if (simFileManager_[slotId] != nullptr) {
        simFileManager_[slotId]->Init(slotId);
    }
    simAccountManager_[slotId] =
        std::make_shared<SimAccountManager>(telRilManager_, simStateManager_[slotId], simFileManager_[slotId]);
    if (simAccountManager_[slotId] != nullptr) {
        simAccountManager_[slotId]->Init(slotId);
    }
}

void SimManager::InitSingleSimObject()
{
    multiSimController_ = std::make_shared<MultiSimController>(telRilManager_, simStateManager_, simFileManager_);
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("SimManager::InitSingleSimObject multiSimController init failed");
        return;
    }
    multiSimController_->Init();
    std::vector<std::weak_ptr<Telephony::SimFileManager>> simFileManager;
    for (auto simFile : simFileManager_) {
        simFileManager.push_back(std::weak_ptr<Telephony::SimFileManager>(simFile));
    }
    multiSimMonitor_ = std::make_shared<MultiSimMonitor>(multiSimController_, simStateManager_, simFileManager);
    if (multiSimMonitor_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager:: multiSimMonitor is null");
        return;
    }
    multiSimMonitor_->Init();
}

int32_t SimManager::HasSimCard(int32_t slotId, bool &hasSimCard)
{
    if ((!IsValidSlotId(slotId, simStateManager_)) || (simStateManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simStateManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (simStateManager_[slotId]->HasSimCard()) {
        hasSimCard = true;
        return TELEPHONY_ERR_SUCCESS;
    }
    return TELEPHONY_ERR_SUCCESS;
}

bool SimManager::HasSimCardInner(int32_t slotId)
{
    bool hasSimCard = false;
    HasSimCard(slotId, hasSimCard);
    return hasSimCard;
}

int32_t SimManager::GetSimState(int32_t slotId, SimState &simState)
{
    if (!HasSimCardInner(slotId)) {
        simState = SimState::SIM_STATE_NOT_PRESENT;
        return TELEPHONY_ERR_SUCCESS;
    }
    simState = simStateManager_[slotId]->GetSimState();
    return TELEPHONY_ERR_SUCCESS;
}

int32_t SimManager::GetCardType(int32_t slotId, CardType &cardType)
{
    if (!HasSimCardInner(slotId)) {
        TELEPHONY_LOGE("slot%{public}d GetCardType has no sim card!", slotId);
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    cardType = simStateManager_[slotId]->GetCardType();
    return TELEPHONY_ERR_SUCCESS;
}

int32_t SimManager::SetModemInit(int32_t slotId, bool state)
{
    if ((!IsValidSlotId(slotId, simStateManager_)) || (simStateManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("slot%{public}d simStateManager_ is nullptr!", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simStateManager_[slotId]->SetModemInit(state);
}

int32_t SimManager::UnlockPin(int32_t slotId, const std::string &pin, LockStatusResponse &response)
{
    if (!HasSimCardInner(slotId)) {
        TELEPHONY_LOGE("UnlockPin has no sim card!");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    return simStateManager_[slotId]->UnlockPin(slotId, pin, response);
}

int32_t SimManager::UnlockPuk(
    int32_t slotId, const std::string &newPin, const std::string &puk, LockStatusResponse &response)
{
    if (!HasSimCardInner(slotId)) {
        TELEPHONY_LOGE("UnlockPuk has no sim card!");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    return simStateManager_[slotId]->UnlockPuk(slotId, newPin, puk, response);
}

int32_t SimManager::AlterPin(
    int32_t slotId, const std::string &newPin, const std::string &oldPin, LockStatusResponse &response)
{
    if (!HasSimCardInner(slotId)) {
        TELEPHONY_LOGE("AlterPin has no sim card!");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    return simStateManager_[slotId]->AlterPin(slotId, newPin, oldPin, response);
}

int32_t SimManager::SetLockState(int32_t slotId, const LockInfo &options, LockStatusResponse &response)
{
    if (!HasSimCardInner(slotId)) {
        TELEPHONY_LOGE("SetLockState has no sim card!");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    return simStateManager_[slotId]->SetLockState(slotId, options, response);
}

int32_t SimManager::GetLockState(int32_t slotId, LockType lockType, LockState &lockState)
{
    if (!HasSimCardInner(slotId)) {
        TELEPHONY_LOGE("GetLockState has no sim card!");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    return simStateManager_[slotId]->GetLockState(slotId, lockType, lockState);
}

int32_t SimManager::RefreshSimState(int32_t slotId)
{
    if ((!IsValidSlotId(slotId, simStateManager_)) || (simStateManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simStateManager is null!");
        return TELEPHONY_ERROR;
    }
    return simStateManager_[slotId]->RefreshSimState(slotId);
}

int32_t SimManager::UnlockPin2(int32_t slotId, const std::string &pin2, LockStatusResponse &response)
{
    if (!HasSimCardInner(slotId)) {
        TELEPHONY_LOGE("UnlockPin2 has no sim card!");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    return simStateManager_[slotId]->UnlockPin2(slotId, pin2, response);
}

int32_t SimManager::UnlockPuk2(
    int32_t slotId, const std::string &newPin2, const std::string &puk2, LockStatusResponse &response)
{
    if (!HasSimCardInner(slotId)) {
        TELEPHONY_LOGE("UnlockPuk2 has no sim card!");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    return simStateManager_[slotId]->UnlockPuk2(slotId, newPin2, puk2, response);
}

int32_t SimManager::AlterPin2(
    int32_t slotId, const std::string &newPin2, const std::string &oldPin2, LockStatusResponse &response)
{
    if (!HasSimCardInner(slotId)) {
        TELEPHONY_LOGE("AlterPin2 has no sim card!");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    return simStateManager_[slotId]->AlterPin2(slotId, newPin2, oldPin2, response);
}

int32_t SimManager::UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo, LockStatusResponse &response)
{
    if (!HasSimCardInner(slotId)) {
        TELEPHONY_LOGE("UnlockSimLock has no sim card!");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    return simStateManager_[slotId]->UnlockSimLock(slotId, lockInfo, response);
}

bool SimManager::IsSimActive(int32_t slotId)
{
    if ((!IsValidSlotId(slotId)) || (multiSimController_ == nullptr)) {
        TELEPHONY_LOGE("slotId is invalid or multiSimController_ is nullptr");
        return false;
    }
    return multiSimController_->IsSimActive(slotId);
}

int32_t SimManager::SetActiveSim(int32_t slotId, int32_t enable)
{
    if ((!IsValidSlotId(slotId)) || (multiSimController_ == nullptr)) {
        TELEPHONY_LOGE("slotId is invalid or multiSimController_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t ret = multiSimController_->SetActiveSim(slotId, enable);
    if (ret == TELEPHONY_ERR_SUCCESS && multiSimMonitor_ != nullptr) {
        multiSimMonitor_->NotifySimAccountChanged();
    }
    return ret;
}

int32_t SimManager::GetSimAccountInfo(int32_t slotId, bool denied, IccAccountInfo &info)
{
    if ((!IsValidSlotId(slotId)) || (multiSimController_ == nullptr)) {
        TELEPHONY_LOGE("slotId is invalid or multiSimController_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return multiSimController_->GetSimAccountInfo(slotId, denied, info);
}

int32_t SimManager::SetDefaultVoiceSlotId(int32_t slotId)
{
    if (!IsValidSlotIdForDefault(slotId)) {
        TELEPHONY_LOGE("slotId is invalid for default.");
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("multiSimController_ is nullptr.");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t ret = multiSimController_->SetDefaultVoiceSlotId(slotId);
    if (ret == TELEPHONY_ERR_SUCCESS && multiSimMonitor_ != nullptr) {
        multiSimMonitor_->NotifySimAccountChanged();
    }
    return ret;
}

int32_t SimManager::SetDefaultSmsSlotId(int32_t slotId)
{
    if (!IsValidSlotIdForDefault(slotId)) {
        TELEPHONY_LOGE("slotId is invalid for default.");
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("multiSimController_ is nullptr.");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t ret = multiSimController_->SetDefaultSmsSlotId(slotId);
    if (ret == TELEPHONY_ERR_SUCCESS && multiSimMonitor_ != nullptr) {
        multiSimMonitor_->NotifySimAccountChanged();
    }
    return ret;
}

int32_t SimManager::SetDefaultCellularDataSlotId(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("slotId is invalid for default.");
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("multiSimController_ is nullptr.");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t ret = multiSimController_->SetDefaultCellularDataSlotId(slotId);
    if (ret == TELEPHONY_ERR_SUCCESS && multiSimMonitor_ != nullptr) {
        multiSimMonitor_->NotifySimAccountChanged();
    }
    return ret;
}

int32_t SimManager::SetPrimarySlotId(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("slotId is invalid for default.");
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("multiSimController_ is nullptr.");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t ret = multiSimController_->SetPrimarySlotId(slotId);
    if (ret == TELEPHONY_ERR_SUCCESS && multiSimMonitor_ != nullptr) {
        multiSimMonitor_->NotifySimAccountChanged();
    }
    return ret;
}

int32_t SimManager::SetShowNumber(int32_t slotId, const std::u16string &number)
{
    if ((!IsValidSlotId(slotId)) || (multiSimController_ == nullptr)) {
        TELEPHONY_LOGE("slotId is invalid or multiSimController_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return multiSimController_->SetShowNumber(slotId, number);
}

int32_t SimManager::SetShowName(int32_t slotId, const std::u16string &name)
{
    if ((!IsValidSlotId(slotId)) || (multiSimController_ == nullptr)) {
        TELEPHONY_LOGE("slotId is invalid or multiSimController_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return multiSimController_->SetShowName(slotId, name);
}

int32_t SimManager::GetDefaultVoiceSlotId()
{
    if (slotCount_ == std::atoi(DEFAULT_SLOT_COUNT)) {
        TELEPHONY_LOGI("default slotId is 0 for single card version");
        return DEFAULT_SIM_SLOT_ID;
    }
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("multiSimController_ is nullptr");
        return TELEPHONY_ERROR;
    }
    return multiSimController_->GetDefaultVoiceSlotId();
}

int32_t SimManager::GetDefaultVoiceSimId(int32_t &simId)
{
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("multiSimController_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t result = multiSimController_->GetDefaultVoiceSlotId();
    if (result < DEFAULT_SIM_SLOT_ID) {
        TELEPHONY_LOGI("DefaultVoiceSlotId is invalid");
        simId = INVALID_VALUE;
        return TELEPHONY_ERR_SUCCESS;
    }
    int32_t defaultSimId = GetSimId(result);
    if (defaultSimId <= DEFAULT_SIM_SLOT_ID) {
        TELEPHONY_LOGI("simId  is invalid");
        simId = INVALID_VALUE;
    } else {
        simId = defaultSimId;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t SimManager::GetDefaultSmsSlotId()
{
    if (slotCount_ == std::atoi(DEFAULT_SLOT_COUNT)) {
        TELEPHONY_LOGI("default slotId is 0 for single card version");
        return DEFAULT_SIM_SLOT_ID;
    }
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("multiSimController_ is nullptr");
        return TELEPHONY_ERROR;
    }
    return multiSimController_->GetDefaultSmsSlotId();
}

int32_t SimManager::GetDefaultSmsSimId(int32_t &simId)
{
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("multiSimController_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t result = multiSimController_->GetDefaultSmsSlotId();
    if (result < DEFAULT_SIM_SLOT_ID) {
        TELEPHONY_LOGI("DefaultSmsSlotId is invalid");
        simId = INVALID_VALUE;
        return TELEPHONY_ERR_SUCCESS;
    }
    int32_t defaultSimId = GetSimId(result);
    if (defaultSimId <= DEFAULT_SIM_SLOT_ID) {
        TELEPHONY_LOGI("simId  is invalid");
        simId = INVALID_VALUE;
    } else {
        simId = defaultSimId;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t SimManager::GetDefaultCellularDataSlotId()
{
    if (slotCount_ == std::atoi(DEFAULT_SLOT_COUNT)) {
        TELEPHONY_LOGI("default slotId is 0 for single card version");
        return DEFAULT_SIM_SLOT_ID;
    }
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("multiSimController_ is nullptr");
        return TELEPHONY_ERROR;
    }
    return multiSimController_->GetDefaultCellularDataSlotId();
}

int32_t SimManager::GetDefaultCellularDataSimId(int32_t &simId)
{
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("multiSimController_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t result = multiSimController_->GetDefaultCellularDataSlotId();
    if (result < DEFAULT_SIM_SLOT_ID) {
        TELEPHONY_LOGE("DefaultCellularDataSlotId is invalid");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    int32_t defaultSimId = GetSimId(result);
    if (defaultSimId <= DEFAULT_SIM_SLOT_ID) {
        TELEPHONY_LOGE("simId  is invalid");
        return TELEPHONY_ERR_FAIL;
    }
    simId = defaultSimId;
    return TELEPHONY_ERR_SUCCESS;
}

int32_t SimManager::GetDsdsMode(int32_t &dsdsMode)
{
    if (slotCount_ == std::atoi(DEFAULT_SLOT_COUNT)) {
        TELEPHONY_LOGI(" default dsds mode is 0 for single card version");
        dsdsMode = DSDS_MODE_V2;
        return TELEPHONY_ERR_SUCCESS;
    }
    dsdsMode = dsdsMode_;
    return TELEPHONY_ERR_SUCCESS;
}

int32_t SimManager::SetDsdsMode(int32_t dsdsMode)
{
    dsdsMode_ = dsdsMode;
    return TELEPHONY_ERR_SUCCESS;
}

int32_t SimManager::GetPrimarySlotId(int32_t &slotId)
{
    if (slotCount_ == std::atoi(DEFAULT_SLOT_COUNT)) {
        TELEPHONY_LOGI(" default slotId is 0 for single card version");
        slotId = DEFAULT_SIM_SLOT_ID;
        return TELEPHONY_ERR_SUCCESS;
    }
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("multiSimController_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    slotId = multiSimController_->GetPrimarySlotId();
    return TELEPHONY_ERR_SUCCESS;
}

int32_t SimManager::GetShowNumber(int32_t slotId, std::u16string &showNumber)
{
    if ((!IsValidSlotId(slotId)) || (multiSimController_ == nullptr)) {
        TELEPHONY_LOGE("slotId is invalid or multiSimController_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return multiSimController_->GetShowNumber(slotId, showNumber);
}

int32_t SimManager::GetShowName(int32_t slotId, std::u16string &showName)
{
    if ((!IsValidSlotId(slotId)) || (multiSimController_ == nullptr)) {
        TELEPHONY_LOGE("slotId is invalid or multiSimController_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return multiSimController_->GetShowName(slotId, showName);
}

int32_t SimManager::GetActiveSimAccountInfoList(bool denied, std::vector<IccAccountInfo> &iccAccountInfoList)
{
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("multiSimController_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return multiSimController_->GetActiveSimAccountInfoList(denied, iccAccountInfoList);
}

int32_t SimManager::GetSlotId(int32_t simId)
{
    if (TELEPHONY_EXT_WRAPPER.getSlotIdExt_) {
        int32_t slotId;
        if (TELEPHONY_EXT_WRAPPER.getSlotIdExt_(simId, slotId)) {
            TELEPHONY_LOGI("getSlotIdExt_, simId:%{public}d, slotId:%{public}d", simId, slotId);
            return slotId;
        }
    }
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("multiSimController_ is nullptr");
        return TELEPHONY_ERROR;
    }
    return multiSimController_->GetSlotId(simId);
}

int32_t SimManager::GetSimId(int32_t slotId)
{
    if (TELEPHONY_EXT_WRAPPER.getSimIdExt_) {
        int32_t simId;
        if (TELEPHONY_EXT_WRAPPER.getSimIdExt_(slotId, simId)) {
            TELEPHONY_LOGI("getSimIdExt_, slotId:%{public}d, simId:%{public}d", slotId, simId);
            return simId;
        }
    }
    IccAccountInfo accountInfo;
    if (GetSimAccountInfo(slotId, false, accountInfo) == TELEPHONY_ERR_SUCCESS) {
        return accountInfo.simId;
    }
    TELEPHONY_LOGE("GetSimAccountInfo fail!");
    return TELEPHONY_ERROR;
}

int32_t SimManager::GetOperatorConfigs(int32_t slotId, OperatorConfig &poc)
{
    if ((!IsValidSlotId(slotId)) || (simAccountManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simAccountManager_[slotId]->GetOperatorConfigs(slotId, poc);
}

int32_t SimManager::UpdateOperatorConfigs(int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if ((!IsValidSlotId(slotId)) || (simAccountManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("slotId %{public}d is invalid or simAccountManager is null!", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simAccountManager_[slotId]->UpdateOperatorConfigs(slotId);
}

int32_t SimManager::HasOperatorPrivileges(const int32_t slotId, bool &hasOperatorPrivileges)
{
    TELEPHONY_LOGI("SimManager::HasOperatorPrivileges slotId:%{public}d", slotId);
    if ((!IsValidSlotId(slotId)) || (simAccountManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simAccountManager_ can not be null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simAccountManager_[slotId]->HasOperatorPrivileges(slotId, hasOperatorPrivileges);
}

int32_t SimManager::SimAuthentication(
    int32_t slotId, AuthType authType, const std::string &authData, SimAuthenticationResponse &response)
{
    if (!HasSimCardInner(slotId)) {
        TELEPHONY_LOGE("SimAuthentication has no sim card!");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if (!IsValidAuthType(authType)) {
        TELEPHONY_LOGE("SimAuthentication authType is invalid!");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    if (simStateManager_[slotId] == nullptr) {
        TELEPHONY_LOGE("simStateManager_ can not be null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simStateManager_[slotId]->SimAuthentication(slotId, authType, authData, response);
}

int32_t SimManager::SendSimMatchedOperatorInfo(
    int32_t slotId, int32_t state, const std::string &operName, const std::string &operKey)
{
    if (simStateManager_.empty() || simStateManager_[slotId] == nullptr) {
        TELEPHONY_LOGE("simStateManager_ can not be null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simStateManager_[slotId]->SendSimMatchedOperatorInfo(slotId, state, operName, operKey);
}

int32_t SimManager::GetRadioProtocolTech(int32_t slotId)
{
    TELEPHONY_LOGI("SimManager::GetRadioProtocolTech slotId:%{public}d", slotId);
    if ((!IsValidSlotId(slotId)) || (multiSimController_ == nullptr)) {
        TELEPHONY_LOGE("slotId is invalid or multiSimController_ is nullptr");
        return static_cast<int32_t>(RadioProtocolTech::RADIO_PROTOCOL_TECH_UNKNOWN);
    }
    return multiSimController_->GetRadioProtocolTech(slotId);
}

void SimManager::GetRadioProtocol(int32_t slotId)
{
    TELEPHONY_LOGI("SimManager::GetRadioProtocol slotId:%{public}d", slotId);
    if ((!IsValidSlotId(slotId)) || (multiSimController_ == nullptr)) {
        TELEPHONY_LOGE("slotId is invalid or multiSimController_ is nullptr");
        return;
    }
    return multiSimController_->GetRadioProtocol(slotId);
}

int32_t SimManager::SendEnvelopeCmd(int32_t slotId, const std::string &cmd)
{
    if ((!IsValidSlotId(slotId)) || (stkManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("stkManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (!HasSimCardInner(slotId)) {
        TELEPHONY_LOGE("SendEnvelopeCmd has no sim card!");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    return stkManager_[slotId]->SendEnvelopeCmd(slotId, cmd);
}

int32_t SimManager::SendTerminalResponseCmd(int32_t slotId, const std::string &cmd)
{
    if ((!IsValidSlotId(slotId)) || (stkManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("stkManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (!HasSimCardInner(slotId)) {
        TELEPHONY_LOGE("SendTerminalResponseCmd has no sim card!");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    return stkManager_[slotId]->SendTerminalResponseCmd(slotId, cmd);
}

int32_t SimManager::SendCallSetupRequestResult(int32_t slotId, bool accept)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("slotId is invalid!");
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    if (stkManager_[slotId] == nullptr) {
        TELEPHONY_LOGE("stkManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (!HasSimCardInner(slotId)) {
        TELEPHONY_LOGE("SendCallSetupRequestResult has no sim card!");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    return stkManager_[slotId]->SendCallSetupRequestResult(slotId, accept);
}

int32_t SimManager::GetSimOperatorNumeric(int32_t slotId, std::u16string &operatorNumeric)
{
    if (!HasSimCardInner(slotId)) {
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if ((!IsValidSlotId(slotId, simFileManager_)) || (simFileManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    operatorNumeric = simFileManager_[slotId]->GetSimOperatorNumeric();
    return TELEPHONY_ERR_SUCCESS;
}

int32_t SimManager::GetISOCountryCodeForSim(int32_t slotId, std::u16string &countryCode)
{
    if (!HasSimCardInner(slotId)) {
        TELEPHONY_LOGE("GetISOCountryCodeForSim has no sim card!");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if ((!IsValidSlotId(slotId, simFileManager_)) || (simFileManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    countryCode = simFileManager_[slotId]->GetISOCountryCodeForSim();
    return TELEPHONY_ERR_SUCCESS;
}

int32_t SimManager::GetSimSpn(int32_t slotId, std::u16string &spn)
{
    if (!HasSimCardInner(slotId)) {
        TELEPHONY_LOGE("GetSimSpn has no sim card!");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if ((!IsValidSlotId(slotId, simFileManager_)) || (simFileManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    spn = simFileManager_[slotId]->GetSimSpn();
    return TELEPHONY_ERR_SUCCESS;
}

std::u16string SimManager::GetSimEons(int32_t slotId, const std::string &plmn, int32_t lac, bool longNameRequired)
{
    if ((!IsValidSlotId(slotId, simFileManager_)) || (simFileManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null");
        return std::u16string();
    }

    return simFileManager_[slotId]->GetSimEons(plmn, lac, longNameRequired);
}

int32_t SimManager::GetSimIccId(int32_t slotId, std::u16string &iccId)
{
    if (!HasSimCardInner(slotId)) {
        TELEPHONY_LOGE("GetSimIccId has no sim card!");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if ((!IsValidSlotId(slotId, simFileManager_)) || (simFileManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    iccId = simFileManager_[slotId]->GetSimIccId();
    return TELEPHONY_ERR_SUCCESS;
}

int32_t SimManager::GetIMSI(int32_t slotId, std::u16string &imsi)
{
    if (!HasSimCardInner(slotId)) {
        TELEPHONY_LOGE("GetIMSI has no sim card!");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if ((!IsValidSlotId(slotId, simFileManager_)) || (simFileManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsi = simFileManager_[slotId]->GetIMSI();
    return TELEPHONY_ERR_SUCCESS;
}

std::u16string SimManager::GetLocaleFromDefaultSim(int32_t slotId)
{
    if ((!IsValidSlotId(slotId, simFileManager_)) || (simFileManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return u"";
    }
    return simFileManager_[slotId]->GetLocaleFromDefaultSim();
}

int32_t SimManager::GetSimGid1(int32_t slotId, std::u16string &gid1)
{
    if (!HasSimCardInner(slotId)) {
        TELEPHONY_LOGE("GetSimGid1 has no sim card!");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if ((!IsValidSlotId(slotId, simFileManager_)) || (simFileManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    gid1 = simFileManager_[slotId]->GetSimGid1();
    return TELEPHONY_ERR_SUCCESS;
}

std::u16string SimManager::GetSimGid2(int32_t slotId)
{
    if ((!IsValidSlotId(slotId, simFileManager_)) || (simFileManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return u"";
    }
    return simFileManager_[slotId]->GetSimGid2();
}

int32_t SimManager::GetOpName(int32_t slotId, std::u16string &opname)
{
    if (!IsValidSlotId(slotId, simFileManager_)) {
        TELEPHONY_LOGE("slotId is invalid! %{public}d", slotId);
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    if (simFileManager_[slotId] == nullptr) {
        TELEPHONY_LOGE("simFileManager is null! %{public}d", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    opname = simFileManager_[slotId]->GetOpName();
    return TELEPHONY_ERR_SUCCESS;
}

int32_t SimManager::GetOpKey(int32_t slotId, std::u16string &opkey)
{
    if (!IsValidSlotId(slotId, simFileManager_)) {
        TELEPHONY_LOGE("slotId is invalid! %{public}d", slotId);
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    if (simFileManager_[slotId] == nullptr) {
        TELEPHONY_LOGE("simFileManager is null! %{public}d", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    opkey = simFileManager_[slotId]->GetOpKey();
    return TELEPHONY_ERR_SUCCESS;
}

int32_t SimManager::GetOpKeyExt(int32_t slotId, std::u16string &opkeyExt)
{
    if (!IsValidSlotId(slotId, simFileManager_)) {
        TELEPHONY_LOGE("slotId is invalid! %{public}d", slotId);
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    if (simFileManager_[slotId] == nullptr) {
        TELEPHONY_LOGE("simFileManager is null! %{public}d", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    opkeyExt = simFileManager_[slotId]->GetOpKeyExt();
    return TELEPHONY_ERR_SUCCESS;
}

int32_t SimManager::GetSimTelephoneNumber(int32_t slotId, std::u16string &telephoneNumber)
{
    if ((!IsValidSlotId(slotId)) || (multiSimController_ == nullptr)) {
        TELEPHONY_LOGE("slotId is invalid or multiSimController_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return multiSimController_->GetSimTelephoneNumber(slotId, telephoneNumber);
}

std::u16string SimManager::GetSimTeleNumberIdentifier(const int32_t slotId)
{
    if ((!IsValidSlotId(slotId)) || (simFileManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return u"";
    }
    return simFileManager_[slotId]->GetSimTeleNumberIdentifier();
}

int32_t SimManager::GetVoiceMailIdentifier(int32_t slotId, std::u16string &voiceMailIdentifier)
{
    if (!HasSimCardInner(slotId)) {
        TELEPHONY_LOGE("GetVoiceMailIdentifier has no sim card!");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if ((!IsValidSlotId(slotId)) || (simFileManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    voiceMailIdentifier = simFileManager_[slotId]->GetVoiceMailIdentifier();
    return TELEPHONY_ERR_SUCCESS;
}

int32_t SimManager::GetVoiceMailNumber(int32_t slotId, std::u16string &voiceMailNumber)
{
    if (!HasSimCardInner(slotId)) {
        TELEPHONY_LOGE("GetVoiceMailNumber has no sim card!");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if ((!IsValidSlotId(slotId)) || (simFileManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    voiceMailNumber = simFileManager_[slotId]->GetVoiceMailNumber();
    return TELEPHONY_ERR_SUCCESS;
}

int32_t SimManager::GetVoiceMailCount(int32_t slotId, int32_t &voiceMailCount)
{
    if (!HasSimCardInner(slotId)) {
        TELEPHONY_LOGE("GetVoiceMailCount has no sim card!");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if ((!IsValidSlotId(slotId)) || (simFileManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    voiceMailCount = simFileManager_[slotId]->GetVoiceMailCount();
    return TELEPHONY_ERR_SUCCESS;
}

int32_t SimManager::SetVoiceMailCount(int32_t slotId, int32_t voiceMailCount)
{
    if (!HasSimCardInner(slotId)) {
        TELEPHONY_LOGE("SetVoiceMailCount has no sim card!");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if ((!IsValidSlotId(slotId)) || (simFileManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (simFileManager_[slotId]->SetVoiceMailCount(voiceMailCount)) {
        return TELEPHONY_ERR_SUCCESS;
    }
    return CORE_ERR_SIM_CARD_UPDATE_FAILED;
}

int32_t SimManager::SetVoiceCallForwarding(int32_t slotId, bool enable, const std::string &number)
{
    if (!HasSimCardInner(slotId)) {
        TELEPHONY_LOGE("SetVoiceCallForwarding has no sim card!");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if ((!IsValidSlotId(slotId)) || (simFileManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (simFileManager_[slotId]->SetVoiceCallForwarding(enable, number)) {
        return TELEPHONY_ERR_SUCCESS;
    }
    return CORE_ERR_SIM_CARD_UPDATE_FAILED;
}

int32_t SimManager::ObtainSpnCondition(int32_t slotId, bool roaming, std::string operatorNum)
{
    if ((!IsValidSlotId(slotId)) || (simFileManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null");
        return TELEPHONY_ERROR;
    }
    return simFileManager_[slotId]->ObtainSpnCondition(roaming, operatorNum);
}

int32_t SimManager::SetVoiceMailInfo(int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber)
{
    if (!HasSimCardInner(slotId)) {
        TELEPHONY_LOGE("SetVoiceMailInfo has no sim card!");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if ((!IsValidSlotId(slotId)) || (simFileManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (!simFileManager_[slotId]->SetVoiceMailInfo(mailName, mailNumber)) {
        return CORE_ERR_SIM_CARD_UPDATE_FAILED;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t SimManager::IsCTSimCard(int32_t slotId, bool &isCTSimCard)
{
    if (!HasSimCardInner(slotId)) {
        TELEPHONY_LOGE("IsCTSimCard has no sim card!");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if ((!IsValidSlotId(slotId)) || (simFileManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    isCTSimCard = simFileManager_[slotId]->IsCTSimCard();
    return TELEPHONY_ERR_SUCCESS;
}

int32_t SimManager::AddSmsToIcc(int32_t slotId, int status, std::string &pdu, std::string &smsc)
{
    if ((!IsValidSlotId(slotId)) || (simSmsManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simSmsManager_ is null!");
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    return simSmsManager_[slotId]->AddSmsToIcc(status, pdu, smsc);
}

int32_t SimManager::UpdateSmsIcc(int32_t slotId, int index, int status, std::string &pduData, std::string &smsc)
{
    if ((!IsValidSlotId(slotId)) || (simSmsManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simSmsManager_ is null!");
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    return simSmsManager_[slotId]->UpdateSmsIcc(index, status, pduData, smsc);
}

int32_t SimManager::DelSmsIcc(int32_t slotId, int index)
{
    if ((!IsValidSlotId(slotId)) || (simSmsManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simSmsManager_ is null!");
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    return simSmsManager_[slotId]->DelSmsIcc(index);
}

std::vector<std::string> SimManager::ObtainAllSmsOfIcc(int32_t slotId)
{
    if ((!IsValidSlotId(slotId)) || (simSmsManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simSmsManager_ is null!");
        std::vector<std::string> result;
        return result;
    }
    return simSmsManager_[slotId]->ObtainAllSmsOfIcc();
}

int32_t SimManager::QueryIccDiallingNumbers(
    int slotId, int type, std::vector<std::shared_ptr<DiallingNumbersInfo>> &result)
{
    if ((!IsValidSlotId(slotId)) || (iccDiallingNumbersManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("iccDiallingNumbersManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return iccDiallingNumbersManager_[slotId]->QueryIccDiallingNumbers(type, result);
}

int32_t SimManager::AddIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    if ((!IsValidSlotId(slotId)) || (iccDiallingNumbersManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("iccDiallingNumbersManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return iccDiallingNumbersManager_[slotId]->AddIccDiallingNumbers(type, diallingNumber);
}

int32_t SimManager::DelIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    if ((!IsValidSlotId(slotId)) || (iccDiallingNumbersManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("iccDiallingNumbersManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return iccDiallingNumbersManager_[slotId]->DelIccDiallingNumbers(type, diallingNumber);
}

int32_t SimManager::UpdateIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    if ((!IsValidSlotId(slotId)) || (iccDiallingNumbersManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("iccDiallingNumbersManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return iccDiallingNumbersManager_[slotId]->UpdateIccDiallingNumbers(type, diallingNumber);
}

void SimManager::RegisterCoreNotify(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what)
{
    if ((what >= RadioEvent::RADIO_IMSI_LOADED_READY) && (what <= RadioEvent::RADIO_SIM_RECORDS_LOADED)) {
        if ((!IsValidSlotId(slotId, simFileManager_)) || (simFileManager_[slotId] == nullptr)) {
            TELEPHONY_LOGE("slotId is invalid or simFileManager_ is nullptr");
            return;
        }
        simFileManager_[slotId]->RegisterCoreNotify(handler, what);
    } else if ((what >= RadioEvent::RADIO_SIM_STATE_CHANGE) && (what <= RadioEvent::RADIO_SIM_STATE_SIMLOCK)) {
        if ((!IsValidSlotId(slotId, simStateManager_)) || (simStateManager_[slotId] == nullptr)) {
            TELEPHONY_LOGE("slotId is invalid or simStateManager_ is nullptr");
            return;
        }
        simStateManager_[slotId]->RegisterCoreNotify(handler, what);
    } else if (what == RadioEvent::RADIO_SIM_ACCOUNT_LOADED) {
        // IsVSimSlotId is used for the callback function can be registered in the VSIM card.
        if ((multiSimMonitor_ == nullptr) || (!IsValidSlotId(slotId) && !multiSimMonitor_->IsVSimSlotId(slotId))) {
            TELEPHONY_LOGE("slotId is invalid or multiSimMonitor_ is nullptr !");
            return;
        }
        multiSimMonitor_->RegisterCoreNotify(slotId, handler, what);
    } else {
        TELEPHONY_LOGE("SimManager::RegisterCoreNotify faild");
    }
}

void SimManager::UnRegisterCoreNotify(
    int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &observerCallBack, int what)
{
    if (what >= RadioEvent::RADIO_IMSI_LOADED_READY && what <= RadioEvent::RADIO_SIM_RECORDS_LOADED) {
        if ((!IsValidSlotId(slotId, simFileManager_)) || (simFileManager_[slotId] == nullptr)) {
            TELEPHONY_LOGE("simFileManager is null");
            return;
        }
        simFileManager_[slotId]->UnRegisterCoreNotify(observerCallBack, what);
    } else if (what >= RadioEvent::RADIO_SIM_STATE_CHANGE && what <= RadioEvent::RADIO_SIM_STATE_SIMLOCK) {
        if ((!IsValidSlotId(slotId, simStateManager_)) || (simStateManager_[slotId] == nullptr)) {
            TELEPHONY_LOGE("simStateManager_ is null");
            return;
        }
        simStateManager_[slotId]->UnRegisterCoreNotify(observerCallBack, what);
    } else {
        TELEPHONY_LOGE("SimManager::UnRegisterCoreNotify faild");
    }
}

bool SimManager::IsValidSlotId(int32_t slotId)
{
    if ((slotId < SLOT_ID_ZERO) || (slotId >= slotCount_)) {
        TELEPHONY_LOGE("slotId is invalid, slotId = %{public}d", slotId);
        return false;
    }
    return true;
}

template<class N>
bool SimManager::IsValidSlotId(int32_t slotId, std::vector<N> vec)
{
    if ((slotId < SLOT_ID_ZERO) || (slotId >= static_cast<int32_t>(vec.size()))) {
        TELEPHONY_LOGE("slotId is invalid by vec.size(), slotId = %{public}d", slotId);
        return false;
    }
    return true;
}

bool SimManager::IsValidAuthType(AuthType authType)
{
    return (authType == AuthType::SIM_AUTH_EAP_SIM_TYPE || authType == AuthType::SIM_AUTH_EAP_AKA_TYPE);
}

bool SimManager::IsValidSlotIdForDefault(int32_t slotId)
{
    if ((slotId < DEFAULT_SIM_SLOT_ID_REMOVE) || (slotId >= slotCount_)) {
        TELEPHONY_LOGE("slotId is invalid, slotId = %{public}d", slotId);
        return false;
    }
    TELEPHONY_LOGD("slotId is valid, slotId = %{public}d", slotId);
    return true;
}

std::u16string SimManager::GetSimIst(int32_t slotId)
{
    if ((!IsValidSlotId(slotId)) || (simFileManager_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return u"";
    }
    return simFileManager_[slotId]->GetSimIst();
}

int32_t SimManager::SaveImsSwitch(int32_t slotId, int32_t imsSwitchValue)
{
    if ((!IsValidSlotId(slotId)) || (multiSimController_ == nullptr)) {
        TELEPHONY_LOGE("slotId is invalid or multiSimController_ is nullptr");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    return multiSimController_->SaveImsSwitch(slotId, imsSwitchValue);
}

int32_t SimManager::QueryImsSwitch(int32_t slotId, int32_t &imsSwitchValue)
{
    if ((!IsValidSlotId(slotId)) || (multiSimController_ == nullptr)) {
        TELEPHONY_LOGE("slotId is invalid or multiSimController_ is nullptr");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    return multiSimController_->QueryImsSwitch(slotId, imsSwitchValue);
}

int32_t SimManager::RegisterSimAccountCallback(const int32_t tokenId, const sptr<SimAccountCallback> &callback)
{
    if (multiSimMonitor_ == nullptr) {
        TELEPHONY_LOGE("multiSimMonitor is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return multiSimMonitor_->RegisterSimAccountCallback(tokenId, callback);
}

int32_t SimManager::UnregisterSimAccountCallback(const int32_t tokenId)
{
    if (multiSimMonitor_ == nullptr) {
        TELEPHONY_LOGE("multiSimMonitor is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return multiSimMonitor_->UnregisterSimAccountCallback(tokenId);
}

bool SimManager::IsSetActiveSimInProgress(int32_t slotId)
{
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("multiSimController_ is nullptr");
        return false;
    }
    return multiSimController_->IsSetActiveSimInProgress(slotId);
}

bool SimManager::IsSetPrimarySlotIdInProgress()
{
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("multiSimController_ is nullptr");
        return false;
    }
    return multiSimController_->IsSetPrimarySlotIdInProgress();
}

int32_t SimManager::GetSimIO(int32_t slotId, int32_t command,
    int32_t fileId, const std::string &data, const std::string &path, SimAuthenticationResponse &response)
{
    if (!HasSimCardInner(slotId)) {
        TELEPHONY_LOGE("SimAuthentication has no sim card!");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if (data.length() < SIM_IO_DATA_MIN_LEN) {
        TELEPHONY_LOGE("SIM IO input data length invalid");
        return TELEPHONY_ERR_FAIL;
    }
    SimIoRequestInfo requestInfo;
    requestInfo.p1 = stoi(data.substr(SIM_IO_DATA_P1_OFFSET, SIM_IO_DATA_STR_LEN), nullptr, SIM_IO_HEX_SIGN);
    requestInfo.p2 = stoi(data.substr(SIM_IO_DATA_P2_OFFSET, SIM_IO_DATA_STR_LEN), nullptr, SIM_IO_HEX_SIGN);
    requestInfo.p3 = stoi(data.substr(SIM_IO_DATA_P3_OFFSET, SIM_IO_DATA_STR_LEN), nullptr, SIM_IO_HEX_SIGN);
    requestInfo.command = command;
    requestInfo.fileId = fileId;
    requestInfo.data = data.substr(SIM_IO_DATA_MIN_LEN, data.length() - SIM_IO_DATA_MIN_LEN);
    requestInfo.path = path;
    return simStateManager_[slotId]->GetSimIO(slotId, requestInfo, response);
}
} // namespace Telephony
} // namespace OHOS
