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
#include "telephony_log.h"

namespace OHOS {
namespace SIM {
SimStateManager::SimStateManager()
{
    simStateRun_ = STATE_NOT_START;
    TELEPHONY_INFO_LOG("SimStateManager::SimStateManager()");
}

void SimStateManager::Init()
{
    std::lock_guard<std::mutex> lck(mtx_);
    TELEPHONY_INFO_LOG("SimStateManager::Init()");
    observerHandler_ = std::make_unique<ObserverHandler>();
    if (observerHandler_ == nullptr) {
        TELEPHONY_INFO_LOG("SimStateManager::failed to create new ObserverHandler");
        return;
    }
    if (simStateRun_ == STATE_RUNNING) {
        TELEPHONY_INFO_LOG("simStateHandle_ is running");
        return;
    }

    eventLoop_ = AppExecFwk::EventRunner::Create("SimStateHandle");
    if (eventLoop_.get() == nullptr) {
        TELEPHONY_INFO_LOG("SimStateHandle  failed to create EventRunner");
        return;
    }

    simStateHandle_ = std::make_shared<SimStateHandle>(eventLoop_, shared_from_this());
    if (simStateHandle_ == nullptr) {
        TELEPHONY_INFO_LOG("SimStateManager::failed to create new SimStateHandle");
        return;
    }
    simStateHandle_->Init();
    eventLoop_->Run();
    TELEPHONY_INFO_LOG("SimStateManager::eventLoop_  is running");
    simStateRun_ = STATE_RUNNING;
}

void SimStateManager::RegisterForIccStateChanged(HANDLE &handler)
{
    std::lock_guard<std::mutex> lck(mtx_);
    TELEPHONY_INFO_LOG("SimStateManager::RegisterForIccChanged()");
    int what = ObserverHandler::RADIO_SIM_STATE_CHANGE;
    observerHandler_->RegObserver(what, handler);
}

void SimStateManager::UnregisterForIccStateChanged(HANDLE &handler)
{
    std::lock_guard<std::mutex> lck(mtx_);
    TELEPHONY_INFO_LOG("SimStateManager::UnregisterForIccChanged()");
    int what = ObserverHandler::RADIO_SIM_STATE_CHANGE;
    observerHandler_->Remove(what);
}

void SimStateManager::RegisterForReady(HANDLE &handler)
{
    std::lock_guard<std::mutex> lck(mtx_);
    TELEPHONY_INFO_LOG("SimStateManager::RegisterForReady()");
    int what = ObserverHandler::RADIO_SIM_STATE_READY;
    observerHandler_->RegObserver(what, handler);
}

void SimStateManager::UnregisterForReady(HANDLE &handler)
{
    std::lock_guard<std::mutex> lck(mtx_);
    TELEPHONY_INFO_LOG("SimStateManager::UnregisterForReady()");
    int what = ObserverHandler::RADIO_SIM_STATE_READY;
    observerHandler_->Remove(what);
}

void SimStateManager::NotifyIccStateChanged()
{
    std::lock_guard<std::mutex> lck(mtx_);
    TELEPHONY_INFO_LOG("SimStateManager::NotifyIccStateChanged()");
    observerHandler_->NotifyObserver(ObserverHandler::RADIO_SIM_STATE_CHANGE);
    return;
}

void SimStateManager::NotifyIccReady()
{
    std::lock_guard<std::mutex> lck(mtx_);
    TELEPHONY_INFO_LOG("SimStateManager::NotifyIccReady()");
    observerHandler_->NotifyObserver(ObserverHandler::RADIO_SIM_STATE_READY);
    return;
}

void SimStateManager::TestSimStateManager()
{
    TELEPHONY_INFO_LOG("SimStateManager::TestSimStateManager()");
}

bool SimStateManager::HasSimCard(int32_t slotId)
{
    std::lock_guard<std::mutex> lck(mtx_);
    TELEPHONY_INFO_LOG("SimStateManager::HasSimCard()");
    return simStateHandle_->HasSimCard(slotId);
}

int32_t SimStateManager::GetSimState(int32_t slotId)
{
    std::lock_guard<std::mutex> lck(mtx_);
    TELEPHONY_INFO_LOG("SimStateManager::GetSimState()");
    return simStateHandle_->GetSimState(slotId);
}

bool SimStateManager::IsSimActive(int32_t slotId)
{
    std::lock_guard<std::mutex> lck(mtx_);
    TELEPHONY_INFO_LOG("SimStateManager::IsSimActive()");
    return true;
}

SimStateManager::~SimStateManager() {}
} // namespace SIM
} // namespace OHOS
