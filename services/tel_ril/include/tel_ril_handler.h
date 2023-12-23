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

#ifndef TEL_RIL_HANDLER_H
#define TEL_RIL_HANDLER_H

#include "event_handler.h"
#include "event_runner.h"
#include "tel_event_handler.h"
#ifdef ABILITY_POWER_SUPPORT
#include "power_mgr_client.h"
#include "power_mgr_errors.h"
#endif

namespace OHOS {
namespace Telephony {
class TelRilHandler : public TelEventHandler {
public:
    TelRilHandler() : TelEventHandler("TelRilHandler") {}
    ~TelRilHandler() = default;

    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event) override;
    void OnInit(void);
    void ApplyRunningLock(int32_t lockType);
    void ReduceRunningLock(int32_t lockType);
    void ReleaseRunningLock(int32_t lockType);

public:
    static const int32_t NORMAL_RUNNING_LOCK = 100;
    static const int32_t ACK_RUNNING_LOCK = 101;

private:
    static const uint32_t RUNNING_LOCK_TIMEOUT_EVENT_ID = 0;
    static const uint32_t ACK_RUNNING_LOCK_TIMEOUT_EVENT_ID = 1;

    static const int64_t RUNNING_LOCK_DEFAULT_TIMEOUT_MS = 60 * 1000; // 60s
    static const int64_t ACK_RUNNING_LOCK_DEFAULT_TIMEOUT_MS = 200; // 200ms
    static const int64_t DELAR_RELEASE_RUNNING_LOCK_TIMEOUT_MS = 5 * 1000; // 5s

private:
#ifdef ABILITY_POWER_SUPPORT
    std::shared_ptr<PowerMgr::RunningLock> reqRunningLock_;
    std::shared_ptr<PowerMgr::RunningLock> ackRunningLock_;
#endif
    std::atomic_uint reqRunningLockCount_;
    std::atomic_int reqLockSerialNum_;
    std::atomic_int ackLockSerialNum_;
    std::mutex mutexRunningLock_;

private:
    void ReleaseRunningLockDelay(int32_t lockType);
};
} // namespace Telephony
} // namespace OHOS
#endif // TEL_RIL_HANDLER_H
