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
SimStateManager::SimStateManager() : simStateRun_(STATE_NOT_START)
{
    TELEPHONY_LOGI("SimStateManager::SimStateManager()");
}

void SimStateManager::Init()
{
    std::lock_guard<std::mutex> lck(mtx_);
    TELEPHONY_LOGE("SimStateManager::Init()");
    observerHandler_ = std::make_unique<ObserverHandler>();
    if (observerHandler_ == nullptr) {
        TELEPHONY_LOGE("SimStateManager::failed to create new ObserverHandler");
        return;
    }
    if (simStateRun_ == STATE_RUNNING) {
        TELEPHONY_LOGE("simStateHandle_ is running");
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
    simStateHandle_->Init();
    eventLoop_->Run();
    TELEPHONY_LOGI("SimStateManager::eventLoop_  is running");
    simStateRun_ = STATE_RUNNING;
}

void SimStateManager::RegisterIccStateChanged(HANDLE &handler)
{
    if (observerHandler_ != nullptr) {
        std::lock_guard<std::mutex> lck(mtx_);
        TELEPHONY_LOGI("SimStateManager::RegisterIccStateChanged()");
        int what = ObserverHandler::RADIO_SIM_STATE_CHANGE;
        observerHandler_->RegObserver(what, handler);
    }
}

void SimStateManager::UnregisterIccStateChanged(HANDLE &handler)
{
    if (observerHandler_ != nullptr) {
        std::lock_guard<std::mutex> lck(mtx_);
        TELEPHONY_LOGI("SimStateManager::UnregisterIccStateChanged()");
        int what = ObserverHandler::RADIO_SIM_STATE_CHANGE;
        observerHandler_->Remove(what, handler);
    }
}

void SimStateManager::RegisterIccReady(HANDLE &handler)
{
    if (observerHandler_ != nullptr) {
        std::lock_guard<std::mutex> lck(mtx_);
        TELEPHONY_LOGI("SimStateManager::RegisterIccReady()");
        int what = ObserverHandler::RADIO_SIM_STATE_READY;
        observerHandler_->RegObserver(what, handler);
    }
}

void SimStateManager::UnregisterIccReady(HANDLE &handler)
{
    if (observerHandler_ != nullptr) {
        std::lock_guard<std::mutex> lck(mtx_);
        TELEPHONY_LOGI("SimStateManager::UnregisterIccReady()");
        int what = ObserverHandler::RADIO_SIM_STATE_READY;
        observerHandler_->Remove(what, handler);
    }
}

void SimStateManager::RegisterIccLocked(HANDLE &handler)
{
    if (observerHandler_ != nullptr) {
        std::lock_guard<std::mutex> lck(mtx_);
        TELEPHONY_LOGI("SimStateManager::RegisterIccLocked()");
        int what = ObserverHandler::RADIO_SIM_STATE_LOCKED;
        observerHandler_->RegObserver(what, handler);
    }
}

void SimStateManager::UnregisterIccLocked(HANDLE &handler)
{
    if (observerHandler_ != nullptr) {
        std::lock_guard<std::mutex> lck(mtx_);
        TELEPHONY_LOGI("SimStateManager::UnregisterIccLocked()");
        int what = ObserverHandler::RADIO_SIM_STATE_LOCKED;
        observerHandler_->Remove(what, handler);
    }
}

void SimStateManager::RegisterIccSimLock(HANDLE &handler)
{
    if (observerHandler_ != nullptr) {
        std::lock_guard<std::mutex> lck(mtx_);
        TELEPHONY_LOGI("SimStateManager::RegisterIccSimLock()");
        int what = ObserverHandler::RADIO_SIM_STATE_SIMLOCK;
        observerHandler_->RegObserver(what, handler);
    }
}

void SimStateManager::UnregisterIccSimLock(HANDLE &handler)
{
    if (observerHandler_ != nullptr) {
        std::lock_guard<std::mutex> lck(mtx_);
        TELEPHONY_LOGI("SimStateManager::UnregisterIccSimLock()");
        int what = ObserverHandler::RADIO_SIM_STATE_SIMLOCK;
        observerHandler_->Remove(what, handler);
    }
}

void SimStateManager::NotifyIccStateChanged()
{
    if (observerHandler_ != nullptr) {
        std::lock_guard<std::mutex> lck(mtx_);
        TELEPHONY_LOGI("SimStateManager::NotifyIccStateChanged()");
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_SIM_STATE_CHANGE);
    }
}

void SimStateManager::NotifyIccReady()
{
    if (observerHandler_ != nullptr) {
        std::lock_guard<std::mutex> lck(mtx_);
        TELEPHONY_LOGI("SimStateManager::NotifyIccReady()");
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_SIM_STATE_READY);
    }
}

void SimStateManager::NotifyIccLock()
{
    if (observerHandler_ != nullptr) {
        std::lock_guard<std::mutex> lck(mtx_);
        TELEPHONY_LOGI("SimStateManager::NotifyIccLock()");
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_SIM_STATE_LOCKED);
    }
}

void SimStateManager::NotifyIccSimLock()
{
    if (observerHandler_ != nullptr) {
        std::lock_guard<std::mutex> lck(mtx_);
        TELEPHONY_LOGI("SimStateManager::NotifyIccSimLock()");
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_SIM_STATE_SIMLOCK);
    }
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

int32_t SimStateManager::GetSimState(int32_t slotId)
{
    int32_t ret = EX_UNKNOWN;
    if (simStateHandle_ != nullptr) {
        std::lock_guard<std::mutex> lck(mtx_);
        TELEPHONY_LOGI("SimStateManager::GetSimState()");
        ret = simStateHandle_->GetSimState(slotId);
    }
    return ret;
}

bool SimStateManager::IsSimActive(int32_t slotId)
{
    std::lock_guard<std::mutex> lck(mtx_);
    TELEPHONY_LOGI("SimStateManager::IsSimActive()");
    return true;
}

bool SimStateManager::UnlockPin(std::string pin, LockStatusResponse &response, int32_t phoneId)
{
    int32_t ret = UNLOCK_OK;
    if (simStateHandle_ != nullptr) {
        std::unique_lock<std::mutex> lck(ctx_);
        TELEPHONY_LOGD("SimStateManager::UnlockPin()");
        responseReady_ = false;
        simStateHandle_->UnlockPin(pin, phoneId);
        while (!responseReady_) {
            TELEPHONY_LOGD("UnlockPin::wait(), response = false");
            cv_.wait(lck);
        }
        ret = simStateHandle_->GetUnlockData().result;
        if (ret != UNLOCK_PIN_PUK_INCORRECT) {
            TELEPHONY_LOGD("SimStateManager::UnlockPin(), %{public}d", ret);
            if (ret) {
                response.result = UNLOCK_FAIL;
            } else {
                response.result = UNLOCK_OK;
            }
            return true;
        }
        responseReady_ = false;
        simStateHandle_->UnlockRemain(phoneId);
        while (!responseReady_) {
            TELEPHONY_LOGD("UnlockRemain::wait(), response = false");
            cv_.wait(lck);
        }
        TELEPHONY_LOGD("SimStateManager::UnlockRemain(), response = true");
        ret = simStateHandle_->GetUnlockData().remain;
        response.remain = ret;
        response.result = UNLOCK_INCORRECT;
    }
    TELEPHONY_LOGD("SimStateManager::UnlockPin(), %{public}d", ret);
    return true;
}

bool SimStateManager::UnlockPuk(std::string newPin, std::string puk, LockStatusResponse &response, int32_t phoneId)
{
    int32_t ret = UNLOCK_OK;
    if (simStateHandle_ != nullptr) {
        std::unique_lock<std::mutex> lck(ctx_);
        TELEPHONY_LOGD("SimStateManager::UnlockPin()");
        responseReady_ = false;
        simStateHandle_->UnlockPuk(newPin, puk, phoneId);
        while (!responseReady_) {
            TELEPHONY_LOGD("UnlockPuk::wait(), response = false");
            cv_.wait(lck);
        }
        ret = simStateHandle_->GetUnlockData().result;
        if (ret != UNLOCK_PIN_PUK_INCORRECT) {
            TELEPHONY_LOGD("SimStateManager::UnlockPuk(), %{public}d", ret);
            if (ret) {
                response.result = UNLOCK_FAIL;
            } else {
                response.result = UNLOCK_OK;
            }
            return true;
        }
        responseReady_ = false;
        simStateHandle_->UnlockRemain(phoneId);
        while (!responseReady_) {
            TELEPHONY_LOGD("UnlockRemain::wait(), response = false");
            cv_.wait(lck);
        }
        TELEPHONY_LOGD("SimStateManager::UnlockRemain(), response = true");
        ret = simStateHandle_->GetUnlockData().remain;
        response.result = UNLOCK_INCORRECT;
        response.remain = ret;
    }
    TELEPHONY_LOGD("SimStateManager::UnlockPuk(), %{public}d", ret);
    return true;
}

bool SimStateManager::AlterPin(
    std::string newPin, std::string oldPin, LockStatusResponse &response, int32_t phoneId)
{
    int32_t ret = UNLOCK_OK;
    if (simStateHandle_ != nullptr) {
        std::unique_lock<std::mutex> lck(ctx_);
        TELEPHONY_LOGD("SimStateManager::AlterPin()");
        responseReady_ = false;
        simStateHandle_->AlterPin(newPin, oldPin, phoneId);
        while (!responseReady_) {
            TELEPHONY_LOGD("AlterPin::wait(), response = false");
            cv_.wait(lck);
        }
        ret = simStateHandle_->GetUnlockData().result;
        if (ret != UNLOCK_PIN_PUK_INCORRECT) {
            TELEPHONY_LOGD("SimStateManager::AlterPin(), %{public}d", ret);
            if (ret) {
                response.result = UNLOCK_FAIL;
            } else {
                response.result = UNLOCK_OK;
            }
            return true;
        }
        responseReady_ = false;
        simStateHandle_->UnlockRemain(phoneId);
        while (!responseReady_) {
            TELEPHONY_LOGD("UnlockRemain::wait(), response = false");
            cv_.wait(lck);
        }
        TELEPHONY_LOGD("SimStateManager::UnlockRemain(), response = true");
        ret = simStateHandle_->GetUnlockData().pinRemain;
        response.result = UNLOCK_INCORRECT;
        response.remain = ret;
    }
    TELEPHONY_LOGD("SimStateManager::AlterPin(), %{public}d", ret);
    return true;
}

bool SimStateManager::SetLockState(std::string pin, int32_t enable, LockStatusResponse &response, int32_t phoneId)
{
    int32_t ret = UNLOCK_OK;
    if (simStateHandle_ != nullptr) {
        std::unique_lock<std::mutex> lck(ctx_);
        TELEPHONY_LOGD("SimStateManager::SetLockState()");
        responseReady_ = false;
        simStateHandle_->SetLockState(pin, enable, phoneId);
        while (!responseReady_) {
            TELEPHONY_LOGD("SetLockState::wait(), response = false");
            cv_.wait(lck);
        }
        ret = simStateHandle_->GetUnlockData().result;
        if (ret != UNLOCK_PIN_PUK_INCORRECT) {
            TELEPHONY_LOGD("SimStateManager::SetLockState(), %{public}d", ret);
            if (ret) {
                response.result = UNLOCK_FAIL;
            } else {
                response.result = UNLOCK_OK;
            }
            return true;
        }
        responseReady_ = false;
        simStateHandle_->UnlockRemain(phoneId);
        while (!responseReady_) {
            TELEPHONY_LOGD("UnlockRemain::wait(), response = false");
            cv_.wait(lck);
        }
        TELEPHONY_LOGD("SimStateManager::UnlockRemain(), response = true");
        ret = simStateHandle_->GetUnlockData().pinRemain;
        response.result = UNLOCK_INCORRECT;
        response.remain = ret;
    }
    TELEPHONY_LOGD("SimStateManager::SetLockState(), %{public}d", ret);
    return true;
}

int32_t SimStateManager::GetLockState(int32_t phoneId)
{
    int32_t ret = 0;
    if (simStateHandle_ != nullptr) {
        std::unique_lock<std::mutex> lck(ctx_);
        TELEPHONY_LOGD("SimStateManager::GetLockState()");
        responseReady_ = false;
        simStateHandle_->GetLockState(phoneId);
        while (!responseReady_) {
            TELEPHONY_LOGD("GetLockState::wait(), response = false");
            cv_.wait(lck);
        }
        ret = simStateHandle_->GetUnlockData().lockState;
    }
    TELEPHONY_LOGD("SimStateManager::GetLockState(), %{public}d", ret);
    return ret;
}

int32_t SimStateManager::RefreshSimState(int32_t slotId)
{
    int32_t ret = 0;
    if (simStateHandle_ != nullptr) {
        std::unique_lock<std::mutex> lck(ctx_);
        TELEPHONY_LOGD("SimStateManager::RefreshSimState()");
        responseReady_ = false;
        simStateHandle_->ObtainRealtimeIccStatus();
        while (!responseReady_) {
            TELEPHONY_LOGD("RefreshSimState::wait(), response = false");
            cv_.wait(lck);
        }
        ret = simStateHandle_->GetSimState(slotId);
    }
    TELEPHONY_LOGD("SimStateManager::RefreshSimState(), %{public}d", ret);
    return ret;
}

SimStateManager::~SimStateManager() {}
} // namespace Telephony
} // namespace OHOS
