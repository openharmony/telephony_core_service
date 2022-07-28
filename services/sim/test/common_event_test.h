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

#ifndef OHOS_COMMON_EVENT_TEST_H
#define OHOS_COMMON_EVENT_TEST_H

#include "common_event_manager.h"
#include "common_event_support.h"
#include "sim_constant.h"

namespace OHOS {
namespace Telephony {
const std::string SIM_STATE_CHANGE_ACTION = "com.hos.action.SIM_STATE_CHANGE";
const std::string DEFAULT_VOICE_SLOTID_CHANGE_ACTION = "com.hos.action.DEFAULT_VOICE_SUBSCRIPTION_CHANGED";
const std::string DEFAULT_SMS_SLOTID_CHANGE_ACTION = "com.hos.action.DEFAULT_SMS_SUBSCRIPTION_CHANGED";
const std::string DEFAULT_DATA_SLOTID_CHANGE_ACTION = "com.hos.action.DEFAULT_DATA_SUBSCRIPTION_CHANGED";
const std::string DEFAULT_MAIN_SLOTID_CHANGE_ACTION = "com.hos.action.MAIN_SUBSCRIPTION_CHANGED";

const std::string ACTION_SESSION_END = "usual.event.telpnony.STK_SESSION_END";
const std::string ACTION_ALPHA_IDENTIFIER = "usual.event.telpnony.STK_ALPHA_IDENTIFIER";
const std::string ACTION_CARD_STATUS_INFORM = "usual.event.telpnony.STK_CARD_STATUS_INFORM";
const std::string ACTION_STK_COMMAND = "usual.event.telpnony.STK_COMMAND";

class CommonEventTest : public EventFwk::CommonEventSubscriber {
public:
    explicit CommonEventTest(const EventFwk::CommonEventSubscribeInfo &sp)
        : EventFwk::CommonEventSubscriber(sp) {}
    ~CommonEventTest() {}

    void OnReceiveEvent(const EventFwk::CommonEventData &data)
    {
        OHOS::EventFwk::Want want = data.GetWant();
        std::string action = want.GetAction();
        if (action == SIM_STATE_CHANGE_ACTION) {
            int32_t slotId = want.GetIntParam(PARAM_SLOTID, DEFAULT_PARAM);
            int32_t state = want.GetIntParam(PARAM_STATE, DEFAULT_PARAM);
            std::string reason = want.GetStringParam(PARAM_REASON);
            int32_t code = data.GetCode();
            std::string event = data.GetData();
            std::cout << "receive a CommonEvent action = " << action << ", slotId = " << slotId
                      << ", state = " << state << ", event = " << event << ", reason = " << reason
                      << ", code = " << code << std::endl;
        } else if (action == DEFAULT_VOICE_SLOTID_CHANGE_ACTION || action == DEFAULT_SMS_SLOTID_CHANGE_ACTION ||
            action == DEFAULT_DATA_SLOTID_CHANGE_ACTION || action == DEFAULT_MAIN_SLOTID_CHANGE_ACTION) {
            int32_t slotId = want.GetIntParam(PARAM_SLOTID, DEFAULT_PARAM);
            int32_t code = data.GetCode();
            std::string event = data.GetData();
            std::cout << "receive a CommonEvent action = " << action << ", code = " << code
                      << ", event = " << event << ", slotId = " << slotId << std::endl;
        } else if (action == ACTION_SESSION_END) {
            int32_t slotId = want.GetIntParam(PARAM_STK_SLOTID, DEFAULT_PARAM);
            int32_t code = data.GetCode();
            std::string event = data.GetData();
            std::cout << "receive a CommonEvent action = " << action << ", slotId = " << slotId
                      << " event = " << event << ", code = " << code << std::endl;
        } else if (action == ACTION_STK_COMMAND) {
            int32_t slotId = want.GetIntParam(PARAM_STK_SLOTID, DEFAULT_PARAM);
            std::string cmdData = want.GetStringParam(PARAM_STK_MSG_CMD);
            int32_t code = data.GetCode();
            std::string event = data.GetData();
            std::cout << "receive a CommonEvent action = " << action << ", slotId = " << slotId
                      << ", cmdData = " << cmdData << ", event = " << event
                      << ", code = " << code << std::endl;
        } else if (action == ACTION_ALPHA_IDENTIFIER) {
            std::cout << "receive a CommonEvent action = " << std::endl;
        } else if (action == ACTION_CARD_STATUS_INFORM) {
            int32_t slotId = want.GetIntParam(PARAM_STK_SLOTID, DEFAULT_PARAM);
            int32_t newSimState = want.GetIntParam(PARAM_STK_CARD_STATUS, DEFAULT_PARAM);
            int32_t code = data.GetCode();
            std::string event = data.GetData();
            std::cout << "receive a CommonEvent action = " << action << ", slotId = " << slotId
                      << ", newSimState = " << newSimState << ", event = " << event
                      << ", code = " << code << std::endl;
        }
    };

private:
    const std::string PARAM_SIMID = "simId";
    const std::string PARAM_SLOTID = "slotId";
    const std::string PARAM_STATE = "state";
    const std::string PARAM_REASON = "reason";

    const std::string PARAM_STK_SLOTID = "slotID";
    const std::string PARAM_STK_MSG_CMD = "msgCmd";
    const std::string PARAM_STK_CARD_STATUS = "cardStatus";
    const std::string PARAM_STK_ALPHA_STRING = "alphaString";

    const int32_t DEFAULT_PARAM = -5;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_COMMON_EVENT_TEST_H
