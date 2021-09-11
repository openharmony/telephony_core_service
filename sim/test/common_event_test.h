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

#ifndef SIM_TEST_COMMON_EVENT_TEST_H
#define SIM_TEST_COMMON_EVENT_TEST_H

#include "common_event_manager.h"
#include "common_event_support.h"
#include "sim_constant.h"

namespace OHOS {
namespace Telephony {
const std::string SIM_STATE_CHANGE_ACTION = "com.hos.action.SIM_STATE_CHANGE";
const std::string DEFAULT_VOICE_SLOTID_CHANGE_ACTION = "com.hos.action.DEFAULT_VOICE_SLOTID_CHANGE";
const std::string DEFAULT_SMS_SLOTID_CHANGE_ACTION = "com.hos.action.DEFAULT_SMS_SLOTID_CHANGE";
class CommonEventTest : public EventFwk::CommonEventSubscriber {
public:
    explicit CommonEventTest(const EventFwk::CommonEventSubscribeInfo &sp)
        : EventFwk::CommonEventSubscriber(sp) {};
    ~CommonEventTest() {};

    void OnReceiveEvent(const EventFwk::CommonEventData &data)
    {
        OHOS::EventFwk::Want want = data.GetWant();
        std::string action = want.GetAction();
        if (action == SIM_STATE_CHANGE_ACTION) {
            int32_t subId = want.GetIntParam(PARAM_SIMID, DEFAULT_PARAM);
            int32_t state = want.GetIntParam(PARAM_STATE, DEFAULT_PARAM);
            std::string reason = want.GetStringParam(PARAM_REASON);
            int32_t code = data.GetCode();
            std::string event = data.GetData();
            std::cout << "receive a CommonEvent action = " << action << ", subId = " << subId
                      << ", state = " << state << ", event = " << event << ", reason = " << reason
                      << ", code = " << code << std::endl;
        } else if (action == DEFAULT_VOICE_SLOTID_CHANGE_ACTION || action == DEFAULT_SMS_SLOTID_CHANGE_ACTION) {
            int32_t subId = want.GetIntParam(PARAM_SUBID, DEFAULT_PARAM);
            int32_t code = data.GetCode();
            std::string event = data.GetData();
            std::cout << "receive a CommonEvent action = " << action << ", code = " << code
                      << ", event = " << event << ", subId = " << subId << std::endl;
        }
    };

private:
    const std::string PARAM_SIMID = "simId";
    const std::string PARAM_SUBID = "subId";
    const std::string PARAM_STATE = "state";
    const std::string PARAM_REASON = "reason";
    const int32_t DEFAULT_PARAM = -5;
};
} // namespace Telephony
} // namespace OHOS
#endif // SIM_TEST_COMMON_EVENT_TEST_H
