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
using CommonEventSupport = OHOS::EventFwk::CommonEventSupport;

enum CommentEventTestIntValue {
    COMMON_EVENT_SIM_STATE_CHANGED,
    COMMON_EVENT_SIM_CARD_DEFAULT_VOICE_SUBSCRIPTION_CHANGED,
    COMMON_EVENT_SIM_CARD_DEFAULT_SMS_SUBSCRIPTION_CHANGED,
    COMMON_EVENT_SIM_CARD_DEFAULT_DATA_SUBSCRIPTION_CHANGED,
    COMMON_EVENT_SIM_CARD_DEFAULT_MAIN_SUBSCRIPTION_CHANGED,
    COMMON_EVENT_STK_SESSION_END,
    COMMON_EVENT_STK_COMMAND,
    COMMON_EVENT_STK_ALPHA_IDENTIFIER,
    COMMON_EVENT_STK_CARD_STATE_CHANGED,
    COMMON_EVENT_TEST_UNKNOWN,
};

class CommonEventTest : public EventFwk::CommonEventSubscriber {
public:
    explicit CommonEventTest(const EventFwk::CommonEventSubscribeInfo &sp)
        : EventFwk::CommonEventSubscriber(sp) {}
    ~CommonEventTest() {}

    int32_t GetCommentEventTestIntValue(std::string &event) const
    {
        auto iter = commentEventTestIntValues_.find(event);
        if (iter == commentEventTestIntValues_.end()) {
            return COMMON_EVENT_TEST_UNKNOWN;
        }
        return iter->second;
    }

    void OnReceiveEvent(const EventFwk::CommonEventData &data)
    {
        OHOS::EventFwk::Want want = data.GetWant();
        std::string action = want.GetAction();
        switch (GetCommentEventTestIntValue(action)) {
            case COMMON_EVENT_SIM_STATE_CHANGED:
                std::cout << "receive a CommonEvent action = " << action
                          << ", slotId = " << want.GetIntParam(PARAM_SLOTID, DEFAULT_PARAM)
                          << ", state = " << want.GetIntParam(PARAM_STATE, DEFAULT_PARAM)
                          << ", reason = " << want.GetStringParam(PARAM_REASON)
                          << ", code = " << data.GetCode()
                          << ", event = " << data.GetData()
                          << std::endl;
                break;
            case COMMON_EVENT_SIM_CARD_DEFAULT_VOICE_SUBSCRIPTION_CHANGED:
            case COMMON_EVENT_SIM_CARD_DEFAULT_SMS_SUBSCRIPTION_CHANGED:
            case COMMON_EVENT_SIM_CARD_DEFAULT_DATA_SUBSCRIPTION_CHANGED:
            case COMMON_EVENT_SIM_CARD_DEFAULT_MAIN_SUBSCRIPTION_CHANGED:
                std::cout << "receive a CommonEvent action = " << action
                          << ", code = " << data.GetCode() << ", event = " << data.GetData()
                          << ", slotId = " << want.GetIntParam(PARAM_SLOTID, DEFAULT_PARAM)
                          << std::endl;
                break;
            case COMMON_EVENT_STK_SESSION_END:
                std::cout << "receive a CommonEvent action = " << action
                          << ", slotId = " << want.GetIntParam(PARAM_STK_SLOTID, DEFAULT_PARAM)
                          << std::endl;
                break;
            case COMMON_EVENT_STK_COMMAND:
                std::cout << "receive a CommonEvent action = " << action
                          << ", slotId = " << want.GetIntParam(PARAM_SLOTID, DEFAULT_PARAM)
                          << ", stkData = " << want.GetStringParam(PARAM_STK_MSG_CMD)
                          << std::endl;
                break;
            case COMMON_EVENT_STK_ALPHA_IDENTIFIER:
                std::cout << "receive a CommonEvent action = " << action
                          << ", slotId = " << want.GetIntParam(PARAM_SLOTID, DEFAULT_PARAM)
                          << ", alphaData = " << want.GetStringParam(PARAM_STK_ALPHA_STRING)
                          << std::endl;
                break;
            case COMMON_EVENT_STK_CARD_STATE_CHANGED:
                std::cout << "receive a CommonEvent action = " << action
                          << ", slotId = " << want.GetIntParam(PARAM_SLOTID, DEFAULT_PARAM)
                          << ", newSimState = " << want.GetStringParam(PARAM_STK_CARD_STATUS)
                          << ", refreshResult = " << want.GetStringParam(PARAM_STK_REFRESH_RESULT)
                          << std::endl;
                break;
            default:
                std::cout << "receive a CommonEvent action = " << action << std::endl;
                break;
        }
    };

private:
    const int32_t DEFAULT_PARAM = -1;
    const std::string PARAM_SLOTID = "slotId";
    const std::string PARAM_STATE = "state";
    const std::string PARAM_REASON = "reason";
    const std::string PARAM_STK_SLOTID = "slotId";
    const std::string PARAM_STK_MSG_CMD = "msgCmd";
    const std::string PARAM_STK_CARD_STATUS = "cardStatus";
    const std::string PARAM_STK_REFRESH_RESULT = "refreshResult";
    const std::string PARAM_STK_ALPHA_STRING = "alphaString";
    const std::map<std::string, CommentEventTestIntValue> commentEventTestIntValues_ = {
        {CommonEventSupport::COMMON_EVENT_SIM_STATE_CHANGED, COMMON_EVENT_SIM_STATE_CHANGED},
        {CommonEventSupport::COMMON_EVENT_SIM_CARD_DEFAULT_VOICE_SUBSCRIPTION_CHANGED,
            COMMON_EVENT_SIM_CARD_DEFAULT_VOICE_SUBSCRIPTION_CHANGED},
        {CommonEventSupport::COMMON_EVENT_SIM_CARD_DEFAULT_SMS_SUBSCRIPTION_CHANGED,
            COMMON_EVENT_SIM_CARD_DEFAULT_SMS_SUBSCRIPTION_CHANGED},
        {CommonEventSupport::COMMON_EVENT_SIM_CARD_DEFAULT_DATA_SUBSCRIPTION_CHANGED,
            COMMON_EVENT_SIM_CARD_DEFAULT_DATA_SUBSCRIPTION_CHANGED},
        {CommonEventSupport::COMMON_EVENT_SIM_CARD_DEFAULT_MAIN_SUBSCRIPTION_CHANGED,
            COMMON_EVENT_SIM_CARD_DEFAULT_MAIN_SUBSCRIPTION_CHANGED},
        {CommonEventSupport::COMMON_EVENT_STK_SESSION_END, COMMON_EVENT_STK_SESSION_END},
        {CommonEventSupport::COMMON_EVENT_STK_COMMAND, COMMON_EVENT_STK_COMMAND},
        {CommonEventSupport::COMMON_EVENT_STK_ALPHA_IDENTIFIER, COMMON_EVENT_STK_ALPHA_IDENTIFIER},
        {CommonEventSupport::COMMON_EVENT_STK_CARD_STATE_CHANGED, COMMON_EVENT_STK_CARD_STATE_CHANGED},
    };
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_COMMON_EVENT_TEST_H
