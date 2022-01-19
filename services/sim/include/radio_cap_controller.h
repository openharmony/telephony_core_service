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

#ifndef OHOS_RADIO_CAP_CONTROLLER_H
#define OHOS_RADIO_CAP_CONTROLLER_H

#include <mutex>
#include <condition_variable>
#include <string_ex.h>

#include "event_handler.h"
#include "event_runner.h"

#include "i_tel_ril_manager.h"
#include "sim_constant.h"

namespace OHOS {
namespace Telephony {
enum {
    SET_PROTOCOL = 0,
    UPDATE_PROTOCOL = 1
};

class RadioCapController : public AppExecFwk::EventHandler {
public:
    RadioCapController(std::shared_ptr<Telephony::ITelRilManager> telRilManager,
        const std::shared_ptr<AppExecFwk::EventRunner> &runner);
    virtual ~RadioCapController();
    void RadioCapControllerWait();
    bool RadioCapControllerPoll();
    bool SetRadioProtocol(int32_t slotId, int32_t protocol);
    bool GetRadioProtocolResponse();
    bool SetActiveSimToRil(int32_t slotId, int32_t type, int32_t enable);
    int32_t GetActiveSimToRilResult();
    void ResetResponse();
    static std::mutex ctx_;
    static std::condition_variable cv_;

private:
    using ProcessFunc = void (RadioCapController::*)(const AppExecFwk::InnerEvent::Pointer &event);
    std::map<int32_t, ProcessFunc> memberFuncMap_;
    void InitMemberFunc();
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    void ClearProtocolCache(SimProtocolRequest&);
    void ProcessProtocolTimeOutDone(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessSetRadioProtocolDone(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessUpdateRadioProtocolDone(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessActiveSimToRilResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessActiveSimTimeOutDone(const AppExecFwk::InnerEvent::Pointer &event);
    void RadioCapControllerContinue();
    void EndCommunicate();
    const static int32_t CLEAR = 0;
    const static int32_t SUCCEED = 0;
    const static int32_t FAILED = 1;
    const static int64_t SET_PROTOCOL_OUT_TIME = 15 * 1000;
    const static int64_t SET_ACTIVE_OUT_TIME = 10 * 1000;
    int32_t maxCount_ = 0;
    int32_t activeResponse_ = 0;
    int32_t count_ = 0;
    int32_t localSlot_ = 0;
    int32_t localProtocol_ = 0;
    std::vector<SimProtocolRequest> oldProtocol_;
    std::vector<SimProtocolRequest> newProtocol_;
    bool responseReady_;
    bool radioProtocolResponse_;
    std::shared_ptr<Telephony::ITelRilManager> telRilManager_ = nullptr;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_RADIO_CAP_CONTROLLER_H