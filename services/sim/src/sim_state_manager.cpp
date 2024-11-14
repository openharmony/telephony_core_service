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

#include "sim_state_manager.h"

#include "core_service_errors.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
std::mutex SimStateManager::mtx_;
constexpr static const int32_t WAIT_TIME_SECOND = 3;
constexpr static const int32_t WAIT_TIME_LONG_SECOND = 20;

SimStateManager::SimStateManager(std::shared_ptr<ITelRilManager> telRilManager)
    : telRilManager_(telRilManager), simStateRun_(STATE_NOT_START)
{
    TELEPHONY_LOGI("SimStateManager::SimStateManager()");
}

void SimStateManager::Init(int32_t slotId)
{
    std::lock_guard<std::mutex> lck(mtx_);
    TELEPHONY_LOGE("SimStateManager::Init()");
    if (simStateRun_ == STATE_RUNNING) {
        TELEPHONY_LOGE("simStateHandle_ is running");
        return;
    }
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("SimStateManager::Init telRilManager_ is null.");
        return;
    }
    simStateHandle_ = std::make_shared<SimStateHandle>(shared_from_this());
    if (simStateHandle_ == nullptr) {
        TELEPHONY_LOGE("SimStateManager::failed to create new SimStateHandle");
        return;
    }
    simStateHandle_->SetRilManager(std::weak_ptr<Telephony::ITelRilManager>(telRilManager_));
    simStateHandle_->Init(slotId);

    TELEPHONY_LOGI("SimStateManager::eventLoop_ is running");
    simStateRun_ = STATE_RUNNING;
}

void SimStateManager::RegisterCoreNotify(const HANDLE &handler, int what)
{
    if (simStateHandle_ == nullptr) {
        TELEPHONY_LOGE("RegisterCoreNotify(), simStateHandle_ is nullptr!!!");
        return;
    }
    std::lock_guard<std::mutex> lck(mtx_);
    simStateHandle_->RegisterCoreNotify(handler, what);
}

void SimStateManager::UnRegisterCoreNotify(const HANDLE &handler, int what)
{
    if (simStateHandle_ == nullptr) {
        TELEPHONY_LOGE("UnRegisterCoreNotify(), simStateHandle_ is nullptr!!!");
        return;
    }
    std::lock_guard<std::mutex> lck(mtx_);
    simStateHandle_->UnRegisterCoreNotify(handler, what);
}

bool SimStateManager::HasSimCard()
{
    bool ret = false;
    if (simStateHandle_ != nullptr) {
        std::lock_guard<std::mutex> lck(mtx_);
        TELEPHONY_LOGD("SimStateManager::HasSimCard");
        ret = simStateHandle_->HasSimCard();
    }
    return ret;
}

SimState SimStateManager::GetSimState()
{
    SimState ret = SimState::SIM_STATE_UNKNOWN;
    if (simStateHandle_ != nullptr) {
        std::lock_guard<std::mutex> lck(mtx_);
        TELEPHONY_LOGD("SimStateManager::GetSimState()");
        ret = simStateHandle_->GetSimState();
    }
    return ret;
}

IccSimStatus SimStateManager::GetSimIccStatus()
{
    IccSimStatus ret = IccSimStatus::ICC_CONTENT_UNKNOWN;
    if (simStateHandle_ != nullptr) {
        std::lock_guard<std::mutex> lck(mtx_);
        TELEPHONY_LOGD("SimStateManager::GetSimIccStatus()");
        ret = simStateHandle_->GetSimIccStatus();
    }
    return ret;
}

void SimStateManager::SetSimState(SimState simState)
{
    if (simStateHandle_ == nullptr) {
        TELEPHONY_LOGI("SimStateManager::SetSimState(), simStateHandle_ is nullptr!!!");
        return;
    }
    std::lock_guard<std::mutex> lck(mtx_);
    simStateHandle_->SetSimState(simState);
}

bool SimStateManager::IfModemInitDone()
{
    if (simStateHandle_ != nullptr) {
        return simStateHandle_->modemInitDone_;
    }
    return false;
}

CardType SimStateManager::GetCardType()
{
    CardType ret = CardType::UNKNOWN_CARD;
    if (simStateHandle_ != nullptr) {
        std::lock_guard<std::mutex> lck(mtx_);
        TELEPHONY_LOGD("SimStateManager::GetCardType()");
        ret = simStateHandle_->GetCardType();
    }
    return ret;
}

std::string SimStateManager::GetIccid()
{
    if (simStateHandle_ != nullptr) {
        std::lock_guard<std::mutex> lck(mtx_);
        return simStateHandle_->GetIccid();
    }
    return "";
}

int32_t SimStateManager::SetModemInit(bool state)
{
    if (simStateHandle_ != nullptr) {
        TELEPHONY_LOGI("state: %{public}d", state);
        simStateHandle_->modemInitDone_ = state;
        return TELEPHONY_ERR_SUCCESS;
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

void SimStateManager::SyncCmdResponse()
{
    std::unique_lock<std::mutex> lck(ctx_);
    responseReady_ = true;
    TELEPHONY_LOGI("SimStateManager::SyncCmdResponse(), responseReady_ = %{public}d", responseReady_);
    cv_.notify_one();
}

void SimStateManager::SyncSimMatchResponse()
{
    std::unique_lock<std::mutex> lck(stx_);
    responseSimMatchReady_ = true;
    TELEPHONY_LOGI(
        "SimStateManager::SyncSimMatchResponse(), responseSimMatchReady = %{public}d", responseSimMatchReady_);
    sv_.notify_one();
}

void SimStateManager::SyncSimUnlockPinResponse()
{
    std::unique_lock<std::mutex> lck(rtx_);
    responseSimUnlockPinReady_ = true;
    TELEPHONY_LOGI(
        "SimStateManager::SyncSimUnlockPinResponse(), responsSimUnlockPinReady = %{public}d", responseSimUnlockPinReady_);
    sv_.notify_one();
}

int32_t SimStateManager::UnlockPin(int32_t slotId, const std::string &pin, LockStatusResponse &response)
{
    if (simStateHandle_ == nullptr) {
        TELEPHONY_LOGE("simStateHandle_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::unique_lock<std::mutex> lck(rtx_);
    TELEPHONY_LOGD("SimStateManager::UnlockPin slotId = %{public}d", slotId);
    responseSimMatchReady_ = false;
    simStateHandle_->UnlockPin(slotId, pin);
    while (!responseSimMatchReady_) {
        TELEPHONY_LOGI("UnlockPin::wait(), response = false");
        if (rv_.wait_for(lck, std::chrono::seconds(WAIT_TIME_LONG_SECOND)) == std::cv_status::timeout) {
            break;
        }
    }
    if (!responseSimMatchReady_) {
        TELEPHONY_LOGE("unlock pin sim update failed");
        return CORE_ERR_SIM_CARD_UPDATE_FAILED;
    }
    int32_t unlockResult = static_cast<int32_t>(simStateHandle_->GetUnlockData().result);
    if (unlockResult == UNLOCK_SUCCESS) {
        response.result = UNLOCK_OK;
    } else if (unlockResult == UNLOCK_PASSWORD_ERR) {
        response.result = UNLOCK_INCORRECT;
    } else {
        response.result = UNLOCK_FAIL;
    }
    response.remain = static_cast<int32_t>(simStateHandle_->GetUnlockData().remain);
    TELEPHONY_LOGI("response.result :%{public}d, remain :%{public}d", response.result, response.remain);
    return (response.result == UNLOCK_FAIL) ? TELEPHONY_ERR_RIL_CMD_FAIL : TELEPHONY_SUCCESS;
}

int32_t SimStateManager::UnlockPuk(
    int32_t slotId, const std::string &newPin, const std::string &puk, LockStatusResponse &response)
{
    if (simStateHandle_ == nullptr) {
        TELEPHONY_LOGE("simStateHandle_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::unique_lock<std::mutex> lck(ctx_);
    TELEPHONY_LOGD("SimStateManager::UnlockPuk slotId = %{public}d", slotId);
    responseReady_ = false;
    simStateHandle_->UnlockPuk(slotId, newPin, puk);
    while (!responseReady_) {
        TELEPHONY_LOGI("UnlockPuk::wait(), response = false");
        if (cv_.wait_for(lck, std::chrono::seconds(WAIT_TIME_LONG_SECOND)) == std::cv_status::timeout) {
            break;
        }
    }
    if (!responseReady_) {
        TELEPHONY_LOGE("unlock puk sim update failed");
        return CORE_ERR_SIM_CARD_UPDATE_FAILED;
    }
    int32_t unlockResult = static_cast<int32_t>(simStateHandle_->GetUnlockData().result);
    if (unlockResult == UNLOCK_SUCCESS) {
        response.result = UNLOCK_OK;
    } else if (unlockResult == UNLOCK_PASSWORD_ERR) {
        response.result = UNLOCK_INCORRECT;
    } else {
        response.result = UNLOCK_FAIL;
    }
    response.remain = static_cast<int32_t>(simStateHandle_->GetUnlockData().remain);
    TELEPHONY_LOGI("response.result :%{public}d, remain :%{public}d", response.result, response.remain);
    return (response.result == UNLOCK_FAIL) ? TELEPHONY_ERR_RIL_CMD_FAIL : TELEPHONY_SUCCESS;
}

int32_t SimStateManager::AlterPin(
    int32_t slotId, const std::string &newPin, const std::string &oldPin, LockStatusResponse &response)
{
    if (simStateHandle_ == nullptr) {
        TELEPHONY_LOGE("simStateHandle_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::unique_lock<std::mutex> lck(ctx_);
    TELEPHONY_LOGD("SimStateManager::AlterPin slotId = %{public}d", slotId);
    responseReady_ = false;
    simStateHandle_->AlterPin(slotId, newPin, oldPin);
    while (!responseReady_) {
        TELEPHONY_LOGI("AlterPin::wait(), response = false");
        if (cv_.wait_for(lck, std::chrono::seconds(WAIT_TIME_SECOND)) == std::cv_status::timeout) {
            break;
        }
    }
    if (!responseReady_) {
        TELEPHONY_LOGE("alter pin sim update failed");
        return CORE_ERR_SIM_CARD_UPDATE_FAILED;
    }
    int32_t unlockResult = static_cast<int32_t>(simStateHandle_->GetUnlockData().result);
    if (unlockResult == UNLOCK_SUCCESS) {
        response.result = UNLOCK_OK;
    } else if (unlockResult == UNLOCK_PASSWORD_ERR) {
        response.result = UNLOCK_INCORRECT;
    } else {
        response.result = UNLOCK_FAIL;
    }
    response.remain = static_cast<int32_t>(simStateHandle_->GetUnlockData().remain);
    TELEPHONY_LOGI("response.result :%{public}d, remain :%{public}d", response.result, response.remain);
    return (response.result == UNLOCK_FAIL) ? TELEPHONY_ERR_RIL_CMD_FAIL : TELEPHONY_SUCCESS;
}

int32_t SimStateManager::SetLockState(int32_t slotId, const LockInfo &options, LockStatusResponse &response)
{
    if (options.lockType != LockType::PIN_LOCK && options.lockType != LockType::FDN_LOCK) {
        TELEPHONY_LOGE("SetLockState lockType is error");
        response.result = UNLOCK_FAIL;
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    if (options.lockState != LockState::LOCK_OFF && options.lockState != LockState::LOCK_ON) {
        TELEPHONY_LOGE("SetLockState lockState is error");
        response.result = UNLOCK_FAIL;
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    if (simStateHandle_ == nullptr) {
        TELEPHONY_LOGE("simStateHandle_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::unique_lock<std::mutex> lck(ctx_);
    TELEPHONY_LOGD("SimStateManager::SetLockState slotId = %{public}d", slotId);
    responseReady_ = false;
    simStateHandle_->SetLockState(slotId, options);
    while (!responseReady_) {
        TELEPHONY_LOGI("SetLockState::wait(), response = false");
        if (cv_.wait_for(lck, std::chrono::seconds(WAIT_TIME_LONG_SECOND)) == std::cv_status::timeout) {
            break;
        }
    }
    if (!responseReady_) {
        TELEPHONY_LOGE("set lock state sim update failed");
        return CORE_ERR_SIM_CARD_UPDATE_FAILED;
    }
    int32_t unlockResult = static_cast<int32_t>(simStateHandle_->GetUnlockData().result);
    if (unlockResult == UNLOCK_SUCCESS) {
        response.result = UNLOCK_OK;
    } else if (unlockResult == UNLOCK_PASSWORD_ERR) {
        response.result = UNLOCK_INCORRECT;
    } else {
        response.result = UNLOCK_FAIL;
    }
    response.remain = static_cast<int32_t>(simStateHandle_->GetUnlockData().remain);
    TELEPHONY_LOGI(
        "SetLockState response.result:%{public}d,response.remain:%{public}d", response.result, response.remain);
    return (response.result == UNLOCK_FAIL) ? TELEPHONY_ERR_RIL_CMD_FAIL : TELEPHONY_SUCCESS;
}

int32_t SimStateManager::GetLockState(int32_t slotId, LockType lockType, LockState &lockState)
{
    if (lockType != LockType::PIN_LOCK && lockType != LockType::FDN_LOCK) {
        TELEPHONY_LOGE("GetLockState lockType is error");
        lockState = LockState::LOCK_ERROR;
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    if (simStateHandle_ == nullptr) {
        TELEPHONY_LOGE("simStateHandle_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::unique_lock<std::mutex> lck(ctx_);
    TELEPHONY_LOGD("SimStateManager::GetLockState slotId = %{public}d", slotId);
    responseReady_ = false;
    simStateHandle_->GetLockState(slotId, lockType);
    while (!responseReady_) {
        TELEPHONY_LOGI("GetLockState::wait, response = false");
        if (cv_.wait_for(lck, std::chrono::seconds(WAIT_TIME_SECOND)) == std::cv_status::timeout) {
            break;
        }
    }
    if (!responseReady_) {
        TELEPHONY_LOGE("get lock state sim load failed");
        return CORE_ERR_SIM_CARD_LOAD_FAILED;
    }
    switch (simStateHandle_->GetUnlockData().lockState) {
        case static_cast<int32_t>(LockState::LOCK_OFF):
            lockState = LockState::LOCK_OFF;
            break;
        case static_cast<int32_t>(LockState::LOCK_ON):
            lockState = LockState::LOCK_ON;
            break;
        default:
            lockState = LockState::LOCK_ERROR;
            break;
    }
    TELEPHONY_LOGI("SimStateManager::GetLockState(), %{public}d", lockState);
    return TELEPHONY_SUCCESS;
}

int32_t SimStateManager::UnlockPin2(int32_t slotId, const std::string &pin2, LockStatusResponse &response)
{
    if (simStateHandle_ == nullptr) {
        TELEPHONY_LOGE("simStateHandle_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::unique_lock<std::mutex> lck(ctx_);
    TELEPHONY_LOGD("SimStateManager::UnlockPin2 slotId = %{public}d", slotId);
    responseReady_ = false;
    simStateHandle_->UnlockPin2(slotId, pin2);
    while (!responseReady_) {
        TELEPHONY_LOGI("UnlockPin2::wait(), response = false");
        if (cv_.wait_for(lck, std::chrono::seconds(WAIT_TIME_SECOND)) == std::cv_status::timeout) {
            break;
        }
    }
    if (!responseReady_) {
        TELEPHONY_LOGE("unlock pin2 sim update failed");
        return CORE_ERR_SIM_CARD_UPDATE_FAILED;
    }
    int32_t unlockResult = static_cast<int32_t>(simStateHandle_->GetUnlockData().result);
    if (unlockResult == UNLOCK_SUCCESS) {
        response.result = UNLOCK_OK;
    } else if (unlockResult == UNLOCK_PASSWORD_ERR) {
        response.result = UNLOCK_INCORRECT;
    } else {
        response.result = UNLOCK_FAIL;
    }
    response.remain = static_cast<int32_t>(simStateHandle_->GetUnlockData().remain);
    TELEPHONY_LOGI("response.result :%{public}d, remain :%{public}d", response.result, response.remain);
    return (response.result == UNLOCK_FAIL) ? TELEPHONY_ERR_RIL_CMD_FAIL : TELEPHONY_SUCCESS;
}

int32_t SimStateManager::UnlockPuk2(
    int32_t slotId, const std::string &newPin2, const std::string &puk2, LockStatusResponse &response)
{
    if (simStateHandle_ == nullptr) {
        TELEPHONY_LOGE("simStateHandle_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::unique_lock<std::mutex> lck(ctx_);
    TELEPHONY_LOGD("SimStateManager::UnlockPuk2 slotId = %{public}d", slotId);
    responseReady_ = false;
    simStateHandle_->UnlockPuk2(slotId, newPin2, puk2);
    while (!responseReady_) {
        TELEPHONY_LOGI("UnlockPuk2::wait(), response = false");
        if (cv_.wait_for(lck, std::chrono::seconds(WAIT_TIME_SECOND)) == std::cv_status::timeout) {
            break;
        }
    }
    if (!responseReady_) {
        TELEPHONY_LOGE("unlock puk2 sim update failed");
        return CORE_ERR_SIM_CARD_UPDATE_FAILED;
    }
    int32_t unlockResult = static_cast<int32_t>(simStateHandle_->GetUnlockData().result);
    if (unlockResult == UNLOCK_SUCCESS) {
        response.result = UNLOCK_OK;
    } else if (unlockResult == UNLOCK_PASSWORD_ERR) {
        response.result = UNLOCK_INCORRECT;
    } else {
        response.result = UNLOCK_FAIL;
    }
    response.remain = static_cast<int32_t>(simStateHandle_->GetUnlockData().remain);
    TELEPHONY_LOGI("response.result :%{public}d, remain :%{public}d", response.result, response.remain);
    return (response.result == UNLOCK_FAIL) ? TELEPHONY_ERR_RIL_CMD_FAIL : TELEPHONY_SUCCESS;
}

int32_t SimStateManager::AlterPin2(
    int32_t slotId, const std::string &newPin2, const std::string &oldPin2, LockStatusResponse &response)
{
    if (simStateHandle_ == nullptr) {
        TELEPHONY_LOGE("simStateHandle_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::unique_lock<std::mutex> lck(ctx_);
    TELEPHONY_LOGD("SimStateManager::AlterPin2 slotId = %{public}d", slotId);
    responseReady_ = false;
    simStateHandle_->AlterPin2(slotId, newPin2, oldPin2);
    while (!responseReady_) {
        TELEPHONY_LOGI("AlterPin2::wait(), response = false");
        if (cv_.wait_for(lck, std::chrono::seconds(WAIT_TIME_SECOND)) == std::cv_status::timeout) {
            break;
        }
    }
    if (!responseReady_) {
        TELEPHONY_LOGE("alter pin2 sim update failed");
        return CORE_ERR_SIM_CARD_UPDATE_FAILED;
    }
    int32_t unlockResult = static_cast<int32_t>(simStateHandle_->GetUnlockData().result);
    if (unlockResult == UNLOCK_SUCCESS) {
        response.result = UNLOCK_OK;
    } else if (unlockResult == UNLOCK_PASSWORD_ERR) {
        response.result = UNLOCK_INCORRECT;
    } else {
        response.result = UNLOCK_FAIL;
    }
    response.remain = static_cast<int32_t>(simStateHandle_->GetUnlockData().remain);
    TELEPHONY_LOGI("response.result :%{public}d, remain :%{public}d", response.result, response.remain);
    return (response.result == UNLOCK_FAIL) ? TELEPHONY_ERR_RIL_CMD_FAIL : TELEPHONY_SUCCESS;
}

int32_t SimStateManager::RefreshSimState(int32_t slotId)
{
    int32_t ret = 0;
    if (simStateHandle_ != nullptr) {
        std::unique_lock<std::mutex> lck(ctx_);
        TELEPHONY_LOGD("SimStateManager::RefreshSimState slotId = %{public}d", slotId);
        responseReady_ = false;
        simStateHandle_->ObtainRealtimeIccStatus(slotId);
        while (!responseReady_) {
            TELEPHONY_LOGI("RefreshSimState::wait(), response = false");
            if (cv_.wait_for(lck, std::chrono::seconds(WAIT_TIME_SECOND)) == std::cv_status::timeout) {
                break;
            }
        }
        ret = static_cast<int32_t>(simStateHandle_->GetSimState());
    }
    TELEPHONY_LOGI("SimStateManager::RefreshSimState(), %{public}d", ret);
    return ret;
}

int32_t SimStateManager::UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo, LockStatusResponse &response)
{
    if (simStateHandle_ == nullptr) {
        TELEPHONY_LOGE("UnlockSimLock(), simStateHandle_ is nullptr!!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::unique_lock<std::mutex> lck(ctx_);
    TELEPHONY_LOGD("SimStateManager::UnlockSimLock slotId = %{public}d", slotId);
    responseReady_ = false;
    simStateHandle_->UnlockSimLock(slotId, lockInfo);
    while (!responseReady_) {
        TELEPHONY_LOGI("UnlockSimLock::wait(), response = false");
        if (cv_.wait_for(lck, std::chrono::seconds(WAIT_TIME_SECOND)) == std::cv_status::timeout) {
            break;
        }
    }
    if (!responseReady_) {
        TELEPHONY_LOGE("sim update failed");
        return CORE_ERR_SIM_CARD_UPDATE_FAILED;
    }
    int32_t ret = simStateHandle_->GetSimlockResponse().result;
    TELEPHONY_LOGI("SimStateManager::UnlockSimLock(), remain: %{public}d", response.remain);
    response.remain = simStateHandle_->GetSimlockResponse().remain;
    if (ret == UNLOCK_PIN_PUK_INCORRECT) {
        TELEPHONY_LOGI("SimStateManager::UnlockSimLock(), pin or puk incorrect");
        response.result = UNLOCK_INCORRECT;
    } else {
        TELEPHONY_LOGI("SimStateManager::UnlockSimLock(), %{public}d", ret);
        if (ret) {
            response.result = UNLOCK_FAIL;
        } else {
            response.result = UNLOCK_OK;
        }
    }
    return (response.result == UNLOCK_FAIL) ? TELEPHONY_ERR_RIL_CMD_FAIL : TELEPHONY_SUCCESS;
}

int32_t SimStateManager::SimAuthentication(
    int32_t slotId, AuthType authType, const std::string &authData, SimAuthenticationResponse &response)
{
    if (simStateHandle_ == nullptr) {
        TELEPHONY_LOGE("SimAuthentication(), simStateHandle_ is nullptr!!!");
        return SIM_AUTH_FAIL;
    }
    std::unique_lock<std::mutex> lck(ctx_);
    responseReady_ = false;
    int32_t ret = SIM_AUTH_FAIL;
    ret = simStateHandle_->SimAuthentication(slotId, authType, authData);
    while (!responseReady_) {
        TELEPHONY_LOGI("SimAuthentication::wait(), response = false");
        if (cv_.wait_for(lck, std::chrono::seconds(WAIT_TIME_SECOND)) == std::cv_status::timeout) {
            break;
        }
    }
    response.sw1 = simStateHandle_->GetSimAuthenticationResponse().sw1;
    response.sw2 = simStateHandle_->GetSimAuthenticationResponse().sw2;
    response.response = simStateHandle_->GetSimAuthenticationResponse().response;
    TELEPHONY_LOGI("SimStateManager::SimAuthentication(), sw1: %{public}d, sw2: %{public}d", response.sw1,
        response.sw2);
    return ret;
}

int32_t SimStateManager::SendSimMatchedOperatorInfo(
    int32_t slotId, int32_t state, const std::string &operName, const std::string &operKey)
{
    if (simStateHandle_ == nullptr) {
        TELEPHONY_LOGE("SendSimMatchedOperatorInfo(), simStateHandle_ is nullptr!!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::unique_lock<std::mutex> lck(stx_);
    responseSimMatchReady_ = false;
    simStateHandle_->SendSimMatchedOperatorInfo(slotId, state, operName, operKey);
    while (!responseSimMatchReady_) {
        TELEPHONY_LOGI("SendSimMatchedOperatorInfo::wait(), response = false");
        if (sv_.wait_for(lck, std::chrono::seconds(WAIT_TIME_SECOND)) == std::cv_status::timeout) {
            break;
        }
    }
    int32_t response = simStateHandle_->GetSendSimMatchedOperatorInfoResponse();
    TELEPHONY_LOGI("SimStateManager::SendSimMatchedOperatorInfo(), response: %{public}d", response);
    return response;
}

int32_t SimStateManager::GetSimIO(
    int32_t slotId, SimIoRequestInfo requestInfo, SimAuthenticationResponse &response)
{
    if (simStateHandle_ == nullptr) {
        TELEPHONY_LOGE("GetSimIO(), simStateHandle_ is nullptr!!!");
        return SIM_AUTH_FAIL;
    }
    std::unique_lock<std::mutex> lck(ctx_);
    responseReady_ = false;
    int32_t ret = SIM_AUTH_FAIL;
    ret = simStateHandle_->GetSimIO(slotId, requestInfo);
    while (!responseReady_) {
        TELEPHONY_LOGI("GetSimIO::wait(), response = false");
        if (cv_.wait_for(lck, std::chrono::seconds(WAIT_TIME_SECOND)) == std::cv_status::timeout) {
            break;
        }
    }
    SimAuthenticationResponse retResponse = simStateHandle_->GetSimIOResponse();
    response.sw1 = retResponse.sw1;
    response.sw2 = retResponse.sw2;
    response.response = retResponse.response;
    TELEPHONY_LOGI("SimStateManager::GetSimIO(), sw1: %{public}d, sw2: %{public}d", response.sw1, response.sw2);
    return ret;
}

SimStateManager::~SimStateManager()
{
    if (simStateHandle_ != nullptr) {
        simStateHandle_->UnInit();
    }
}
} // namespace Telephony
} // namespace OHOS
