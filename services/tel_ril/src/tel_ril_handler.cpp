/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "tel_ril_handler.h"

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
void TelRilHandler::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("ProcessEvent, event is nullptr");
        return;
    }
    auto id = event->GetInnerEventId();
    auto serial = event->GetParam();
    TELEPHONY_LOGI(
        "ProcessEvent, id:%{public}d, serial:%{public}d, reqLockSerialNum_:%{public}d, ackLockSerialNum_:%{public}d",
        id, (int)serial, (int)reqLockSerialNum_, (int)ackLockSerialNum_);
    switch (id) {
        case RUNNING_LOCK_TIMEOUT_EVENT_ID:
            if (serial == reqLockSerialNum_) {
                TELEPHONY_LOGI("Running lock timeout, release running lock!!!");
                ReleaseRunningLock(NORMAL_RUNNING_LOCK);
            }
            break;
        case ACK_RUNNING_LOCK_TIMEOUT_EVENT_ID:
            if (serial == ackLockSerialNum_) {
                TELEPHONY_LOGI("Ack Running lock timeout, release running lock!!!");
                ReleaseRunningLock(ACK_RUNNING_LOCK);
            }
            break;
        default:
            TELEPHONY_LOGW("ProcessEvent, invalid id:%{public}d.", id);
            break;
    }
}

void TelRilHandler::OnInit(void)
{
    auto &powerMgrClient = PowerMgr::PowerMgrClient::GetInstance();
    ackRunningLock_ =
        powerMgrClient.CreateRunningLock("telRilAckRunningLock", PowerMgr::RunningLockType::RUNNINGLOCK_BACKGROUND);
    reqRunningLock_ = powerMgrClient.CreateRunningLock(
        "telRilRequestRunningLock", PowerMgr::RunningLockType::RUNNINGLOCK_BACKGROUND);
    reqRunningLockCount_ = 0;
    reqLockSerialNum_ = 0;
    ackLockSerialNum_ = 0;
}

void TelRilHandler::ApplyRunningLock(int32_t lockType)
{
    if (ackRunningLock_ == nullptr) {
        auto &powerMgrClient = PowerMgr::PowerMgrClient::GetInstance();
        ackRunningLock_ = powerMgrClient.CreateRunningLock(
            "telRilAckRunningLock", PowerMgr::RunningLockType::RUNNINGLOCK_BACKGROUND);
        ackLockSerialNum_ = 0;
    }
    if (reqRunningLock_ == nullptr) {
        auto &powerMgrClient = PowerMgr::PowerMgrClient::GetInstance();
        reqRunningLock_ = powerMgrClient.CreateRunningLock(
            "telRilRequestRunningLock", PowerMgr::RunningLockType::RUNNINGLOCK_BACKGROUND);
        reqRunningLockCount_ = 0;
        reqLockSerialNum_ = 0;
    }
    std::lock_guard<std::mutex> lockRequest(mutexRunningLock_);
    if ((reqRunningLock_ != nullptr) && (lockType == NORMAL_RUNNING_LOCK)) {
        reqRunningLockCount_++;
        reqLockSerialNum_++;
        reqRunningLock_->Lock();
        TELEPHONY_LOGI("ApplyRunningLock,reqLockSerialNum_:%{public}d", (int)reqLockSerialNum_);
        this->SendEvent(RUNNING_LOCK_TIMEOUT_EVENT_ID, reqLockSerialNum_, RUNNING_LOCK_DEFAULT_TIMEOUT_MS);
    } else if (ackRunningLock_ != nullptr && lockType == ACK_RUNNING_LOCK) {
        ackLockSerialNum_++;
        ackRunningLock_->Lock();
        TELEPHONY_LOGI("ApplyRunningLock,ackLockSerialNum_:%{public}d", (int)ackLockSerialNum_);
        this->SendEvent(ACK_RUNNING_LOCK_TIMEOUT_EVENT_ID, ackLockSerialNum_, ACK_RUNNING_LOCK_DEFAULT_TIMEOUT_MS);
    } else {
        TELEPHONY_LOGE("ApplyRunningLock,lockType:%{public}d is invalid", lockType);
    }
}

void TelRilHandler::ReduceRunningLock(int32_t lockType)
{
    std::lock_guard<std::mutex> lockRequest(mutexRunningLock_);
    TELEPHONY_LOGI("ReduceRunningLock,reqRunningLockCount_:%{public}d", (int)reqRunningLockCount_);
    if ((reqRunningLock_ != nullptr) && (lockType == NORMAL_RUNNING_LOCK)) {
        if (reqRunningLockCount_ > 1) {
            reqRunningLockCount_--;
        } else {
            reqRunningLockCount_ = 0;
            TELEPHONY_LOGI("ReduceRunningLock, UnLock");
            reqRunningLock_->UnLock();
        }
    } else {
        TELEPHONY_LOGW("ReduceRunningLock type %{public}d don't processe.", lockType);
    }
}

void TelRilHandler::ReleaseRunningLock(int32_t lockType)
{
    if (reqRunningLock_ == nullptr || ackRunningLock_ == nullptr) {
        TELEPHONY_LOGE("reqRunningLock_ or ackRunningLock_ is nullptr");
        return;
    }
    std::lock_guard<std::mutex> lockRequest(mutexRunningLock_);
    TELEPHONY_LOGI("ReleaseRunningLock,lockType:%{public}d", lockType);
    if (lockType == NORMAL_RUNNING_LOCK) {
        reqRunningLockCount_ = 0;
        reqRunningLock_->UnLock();
    } else if (lockType == ACK_RUNNING_LOCK) {
        ackRunningLock_->UnLock();
    } else {
        TELEPHONY_LOGE("ReleaseRunningLock, lockType:%{public}d is invalid", lockType);
    }
}
} // namespace Telephony
} // namespace OHOS