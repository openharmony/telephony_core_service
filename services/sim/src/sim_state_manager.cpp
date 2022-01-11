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
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
std::mutex SimStateManager::mtx_;

SimStateManager::SimStateManager(std::shared_ptr<ITelRilManager> telRilManager)
    : telRilManager_(telRilManager), simStateRun_(STATE_NOT_START)
{
    TELEPHONY_LOGI("SimStateManager::SimStateManager()");
}

void SimStateManager::Init()
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
    eventLoop_ = AppExecFwk::EventRunner::Create("SimStateHandle");
    if (eventLoop_.get() == nullptr) {
        TELEPHONY_LOGE("SimStateHandle  failed to create EventRunner");
        return;
    }
    simStateHandle_ = std::make_shared<SimStateHandle>(eventLoop_, shared_from_this());
    if (simStateHandle_ == nullptr) {
        TELEPHONY_LOGE("SimStateManager::failed to create new SimStateHandle");
        return;
    }
    simStateHandle_->SetRilManager(telRilManager_);
    simStateHandle_->Init();
    eventLoop_->Run();
    TELEPHONY_LOGI("SimStateManager::eventLoop_  is running");
    simStateRun_ = STATE_RUNNING;
}

void SimStateManager::RegisterCoreNotify(const HANDLE &handler, int what)
{
    std::lock_guard<std::mutex> lck(mtx_);
    simStateHandle_->RegisterCoreNotify(handler, what);
}

void SimStateManager::UnRegisterCoreNotify(const HANDLE &handler, int what)
{
    std::lock_guard<std::mutex> lck(mtx_);
    simStateHandle_->UnRegisterCoreNotify(handler, what);
}

bool SimStateManager::HasSimCard(int32_t slotId)
{
    bool ret = false;
    if (simStateHandle_ != nullptr) {
        std::lock_guard<std::mutex> lck(mtx_);
        TELEPHONY_LOGI("SimStateManager::HasSimCard()");
        ret = simStateHandle_->HasSimCard(slotId);
    }
    return ret;
}

SimState SimStateManager::GetSimState(int32_t slotId)
{
    SimState ret = SimState::SIM_STATE_UNKNOWN;
    if (simStateHandle_ != nullptr) {
        std::lock_guard<std::mutex> lck(mtx_);
        TELEPHONY_LOGI("SimStateManager::GetSimState()");
        ret = simStateHandle_->GetSimState(slotId);
    }
    return ret;
}

CardType SimStateManager::GetCardType(int32_t slotId)
{
    CardType ret = CardType::UNKNOWN_CARD;
    if (simStateHandle_ != nullptr) {
        std::lock_guard<std::mutex> lck(mtx_);
        TELEPHONY_LOGI("SimStateManager::GetCardType()");
        ret = simStateHandle_->GetCardType(slotId);
    }
    return ret;
}

bool SimStateManager::UnlockPin(int32_t slotId, std::string pin, LockStatusResponse &response)
{
    int32_t ret = UNLOCK_OK;
    if (simStateHandle_ != nullptr) {
        std::unique_lock<std::mutex> lck(ctx_);
        TELEPHONY_LOGI("SimStateManager::UnlockPin()");
        responseReady_ = false;
        simStateHandle_->UnlockPin(slotId, pin);
        while (!responseReady_) {
            TELEPHONY_LOGI("UnlockPin::wait(), response = false");
            cv_.wait(lck);
        }
        ret = simStateHandle_->GetUnlockData().result;
        if (ret != UNLOCK_PIN_PUK_INCORRECT) {
            TELEPHONY_LOGI("SimStateManager::UnlockPin(), %{public}d", ret);
            if (ret) {
                response.result = UNLOCK_FAIL;
            } else {
                response.result = UNLOCK_OK;
            }
            return true;
        }
        responseReady_ = false;
        simStateHandle_->UnlockRemain(slotId);
        while (!responseReady_) {
            TELEPHONY_LOGI("UnlockRemain::wait(), response = false");
            cv_.wait(lck);
        }
        TELEPHONY_LOGI("SimStateManager::UnlockRemain(), response = true");
        ret = simStateHandle_->GetUnlockData().remain;
        response.remain = ret;
        response.result = UNLOCK_INCORRECT;
    }
    TELEPHONY_LOGI("SimStateManager::UnlockPin(), %{public}d", ret);
    return true;
}

bool SimStateManager::UnlockPuk(int32_t slotId, std::string newPin, std::string puk, LockStatusResponse &response)
{
    int32_t ret = UNLOCK_OK;
    if (simStateHandle_ != nullptr) {
        std::unique_lock<std::mutex> lck(ctx_);
        TELEPHONY_LOGI("SimStateManager::UnlockPuk()");
        responseReady_ = false;
        simStateHandle_->UnlockPuk(slotId, newPin, puk);
        while (!responseReady_) {
            TELEPHONY_LOGI("UnlockPuk::wait(), response = false");
            cv_.wait(lck);
        }
        ret = simStateHandle_->GetUnlockData().result;
        if (ret != UNLOCK_PIN_PUK_INCORRECT) {
            TELEPHONY_LOGI("SimStateManager::UnlockPuk(), %{public}d", ret);
            if (ret) {
                response.result = UNLOCK_FAIL;
            } else {
                response.result = UNLOCK_OK;
            }
            return true;
        }
        responseReady_ = false;
        simStateHandle_->UnlockRemain(slotId);
        while (!responseReady_) {
            TELEPHONY_LOGI("UnlockRemain::wait(), response = false");
            cv_.wait(lck);
        }
        TELEPHONY_LOGI("SimStateManager::UnlockRemain(), response = true");
        ret = simStateHandle_->GetUnlockData().remain;
        response.result = UNLOCK_INCORRECT;
        response.remain = ret;
    }
    TELEPHONY_LOGI("SimStateManager::UnlockPuk(), %{public}d", ret);
    return true;
}

bool SimStateManager::AlterPin(int32_t slotId, std::string newPin, std::string oldPin, LockStatusResponse &response)
{
    int32_t ret = UNLOCK_OK;
    if (simStateHandle_ != nullptr) {
        std::unique_lock<std::mutex> lck(ctx_);
        TELEPHONY_LOGI("SimStateManager::AlterPin()");
        responseReady_ = false;
        simStateHandle_->AlterPin(slotId, newPin, oldPin);
        while (!responseReady_) {
            TELEPHONY_LOGI("AlterPin::wait(), response = false");
            cv_.wait(lck);
        }
        ret = simStateHandle_->GetUnlockData().result;
        if (ret != UNLOCK_PIN_PUK_INCORRECT) {
            TELEPHONY_LOGI("SimStateManager::AlterPin(), %{public}d", ret);
            if (ret) {
                response.result = UNLOCK_FAIL;
            } else {
                response.result = UNLOCK_OK;
            }
            return true;
        }
        responseReady_ = false;
        simStateHandle_->UnlockRemain(slotId);
        while (!responseReady_) {
            TELEPHONY_LOGI("UnlockRemain::wait(), response = false");
            cv_.wait(lck);
        }
        TELEPHONY_LOGI("SimStateManager::UnlockRemain(), response = true");
        ret = simStateHandle_->GetUnlockData().pinRemain;
        response.result = UNLOCK_INCORRECT;
        response.remain = ret;
    }
    TELEPHONY_LOGI("SimStateManager::AlterPin(), %{public}d", ret);
    return true;
}

bool SimStateManager::SetLockState(int32_t slotId, const LockInfo &options, LockStatusResponse &response)
{
    int32_t ret = UNLOCK_OK;
    if (simStateHandle_ != nullptr) {
        std::unique_lock<std::mutex> lck(ctx_);
        TELEPHONY_LOGI("SimStateManager::SetLockState()");
        responseReady_ = false;
        simStateHandle_->SetLockState(slotId, options);
        while (!responseReady_) {
            TELEPHONY_LOGI("SetLockState::wait(), response = false");
            cv_.wait(lck);
        }
        ret = simStateHandle_->GetUnlockData().result;
        if (ret != UNLOCK_PIN_PUK_INCORRECT) {
            TELEPHONY_LOGI("SimStateManager::SetLockState(), %{public}d", ret);
            if (ret) {
                response.result = UNLOCK_FAIL;
            } else {
                response.result = UNLOCK_OK;
            }
            return true;
        }
        responseReady_ = false;
        simStateHandle_->UnlockRemain(slotId);
        while (!responseReady_) {
            TELEPHONY_LOGI("UnlockRemain::wait(), response = false");
            cv_.wait(lck);
        }
        TELEPHONY_LOGI("SimStateManager::UnlockRemain(), response = true");
        if (LockType::PIN_LOCK == options.lockType) {
            ret = simStateHandle_->GetUnlockData().pinRemain;
        } else {
            ret = simStateHandle_->GetUnlockData().pin2Remain;
        }
        response.result = UNLOCK_INCORRECT;
        response.remain = ret;
    }
    TELEPHONY_LOGI("SimStateManager::SetLockState(), %{public}d", ret);
    return true;
}

int32_t SimStateManager::GetLockState(int32_t slotId, LockType lockType)
{
    int32_t ret = 0;
    if (simStateHandle_ != nullptr) {
        std::unique_lock<std::mutex> lck(ctx_);
        TELEPHONY_LOGI("SimStateManager::GetLockState()");
        responseReady_ = false;
        simStateHandle_->GetLockState(slotId, lockType);
        while (!responseReady_) {
            TELEPHONY_LOGI("GetLockState::wait(), response = false");
            cv_.wait(lck);
        }
        ret = simStateHandle_->GetUnlockData().lockState;
    }
    TELEPHONY_LOGI("SimStateManager::GetLockState(), %{public}d", ret);
    return ret;
}

bool SimStateManager::UnlockPin2(int32_t slotId, std::string pin2, LockStatusResponse &response)
{
    int32_t ret = UNLOCK_OK;
    if (simStateHandle_ != nullptr) {
        std::unique_lock<std::mutex> lck(ctx_);
        TELEPHONY_LOGI("SimStateManager::UnlockPin2()");
        responseReady_ = false;
        simStateHandle_->UnlockPin2(slotId, pin2);
        while (!responseReady_) {
            TELEPHONY_LOGI("UnlockPin2::wait(), response = false");
            cv_.wait(lck);
        }
        ret = simStateHandle_->GetUnlockData().result;
        if (ret != UNLOCK_PIN_PUK_INCORRECT) {
            TELEPHONY_LOGI("SimStateManager::UnlockPin2(), %{public}d", ret);
            if (ret) {
                response.result = UNLOCK_FAIL;
            } else {
                response.result = UNLOCK_OK;
            }
            return true;
        }
        responseReady_ = false;
        simStateHandle_->UnlockRemain(slotId);
        while (!responseReady_) {
            TELEPHONY_LOGI("UnlockRemain::wait(), response = false");
            cv_.wait(lck);
        }
        TELEPHONY_LOGI("SimStateManager::UnlockRemain(), response = true");
        ret = simStateHandle_->GetUnlockData().pin2Remain;
        response.remain = ret;
        response.result = UNLOCK_INCORRECT;
    }
    TELEPHONY_LOGI("SimStateManager::UnlockPin2(), %{public}d", ret);
    return true;
}

bool SimStateManager::UnlockPuk2(
    int32_t slotId, std::string newPin2, std::string puk2, LockStatusResponse &response)
{
    int32_t ret = UNLOCK_OK;
    if (simStateHandle_ != nullptr) {
        std::unique_lock<std::mutex> lck(ctx_);
        TELEPHONY_LOGI("SimStateManager::UnlockPuk2()");
        responseReady_ = false;
        simStateHandle_->UnlockPuk2(slotId, newPin2, puk2);
        while (!responseReady_) {
            TELEPHONY_LOGI("UnlockPuk2::wait(), response = false");
            cv_.wait(lck);
        }
        ret = simStateHandle_->GetUnlockData().result;
        if (ret != UNLOCK_PIN_PUK_INCORRECT) {
            TELEPHONY_LOGI("SimStateManager::UnlockPuk2(), %{public}d", ret);
            if (ret) {
                response.result = UNLOCK_FAIL;
            } else {
                response.result = UNLOCK_OK;
            }
            return true;
        }
        responseReady_ = false;
        simStateHandle_->UnlockRemain(slotId);
        while (!responseReady_) {
            TELEPHONY_LOGI("UnlockRemain::wait(), response = false");
            cv_.wait(lck);
        }
        TELEPHONY_LOGI("SimStateManager::UnlockRemain(), response = true");
        ret = simStateHandle_->GetUnlockData().puk2Remain;
        response.result = UNLOCK_INCORRECT;
        response.remain = ret;
    }
    TELEPHONY_LOGI("SimStateManager::UnlockPuk2(), %{public}d", ret);
    return true;
}

bool SimStateManager::AlterPin2(
    int32_t slotId, std::string newPin2, std::string oldPin2, LockStatusResponse &response)
{
    int32_t ret = UNLOCK_OK;
    if (simStateHandle_ != nullptr) {
        std::unique_lock<std::mutex> lck(ctx_);
        TELEPHONY_LOGI("SimStateManager::AlterPin2()");
        responseReady_ = false;
        simStateHandle_->AlterPin2(slotId, newPin2, oldPin2);
        while (!responseReady_) {
            TELEPHONY_LOGI("AlterPin2::wait(), response = false");
            cv_.wait(lck);
        }
        ret = simStateHandle_->GetUnlockData().result;
        if (ret != UNLOCK_PIN_PUK_INCORRECT) {
            TELEPHONY_LOGI("SimStateManager::AlterPin2(), %{public}d", ret);
            if (ret) {
                response.result = UNLOCK_FAIL;
            } else {
                response.result = UNLOCK_OK;
            }
            return true;
        }
        responseReady_ = false;
        simStateHandle_->UnlockRemain(slotId);
        while (!responseReady_) {
            TELEPHONY_LOGI("UnlockRemain::wait(), response = false");
            cv_.wait(lck);
        }
        TELEPHONY_LOGI("SimStateManager::UnlockRemain(), response = true");
        ret = simStateHandle_->GetUnlockData().pin2Remain;
        response.result = UNLOCK_INCORRECT;
        response.remain = ret;
    }
    TELEPHONY_LOGI("SimStateManager::AlterPin2(), %{public}d", ret);
    return true;
}

int32_t SimStateManager::RefreshSimState(int32_t slotId)
{
    int32_t ret = 0;
    if (simStateHandle_ != nullptr) {
        std::unique_lock<std::mutex> lck(ctx_);
        TELEPHONY_LOGI("SimStateManager::RefreshSimState()");
        responseReady_ = false;
        simStateHandle_->ObtainRealtimeIccStatus();
        while (!responseReady_) {
            TELEPHONY_LOGI("RefreshSimState::wait(), response = false");
            cv_.wait(lck);
        }
        ret = static_cast<int32_t>(simStateHandle_->GetSimState(slotId));
    }
    TELEPHONY_LOGI("SimStateManager::RefreshSimState(), %{public}d", ret);
    return ret;
}

bool SimStateManager::UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo,
    LockStatusResponse &response)
{
    if (simStateHandle_ == nullptr) {
        TELEPHONY_LOGE("UnlockSimLock(), simStateHandle_ is nullptr!!!");
        return false;
    }
    int32_t ret = UNLOCK_OK;
    std::unique_lock<std::mutex> lck(ctx_);
    TELEPHONY_LOGI("SimStateManager::UnlockSimLock()");
    responseReady_ = false;
    simStateHandle_->UnlockSimLock(slotId, lockInfo);
    while (!responseReady_) {
        TELEPHONY_LOGI("UnlockSimLock::wait(), response = false");
        cv_.wait(lck);
    }
    ret = simStateHandle_->GetSimlockResponse().result;
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
    return true;
}

SimStateManager::~SimStateManager() {}
} // namespace Telephony
} // namespace OHOS
