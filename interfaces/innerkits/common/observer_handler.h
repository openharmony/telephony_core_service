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

#ifndef OBSERVER_HANDLER_H
#define OBSERVER_HANDLER_H

#include <string>
#include <unordered_map>
#include <vector>
#include "event_handler.h"
#include "event_runner.h"
#include "hilog/log.h"

static constexpr OHOS::HiviewDFX::HiLogLabel OBSERVER_LABEL = {LOG_CORE, 1, "ObserverHandler"};

namespace OHOS {
class ObserverHandler {
public:
    ObserverHandler();

    virtual ~ObserverHandler();

    void RegObserver(int what, const std::shared_ptr<AppExecFwk::EventHandler> handler);

    void RegUniqueObserver(int what, const std::shared_ptr<AppExecFwk::EventHandler> handler);

    void Remove(int what);

    void RemoveAll();

    void NotifyObserver(int what);

    template<typename T>
    void NotifyObserver(int what, T *object)
    {
        auto iter = observerHandlerMap_.find(what);
        if (iter == observerHandlerMap_.end()) {
            OHOS::HiviewDFX::HiLog::Info(OBSERVER_LABEL, "gesture %{public}d not register", what);
            return;
        }
        std::shared_ptr<T> msg(object);

        for (auto handlers : iter->second) {
            OHOS::HiviewDFX::HiLog::Info(OBSERVER_LABEL, "zjy handlers->SendEvent:%{public}d", what);
            handlers->SendEvent(what, msg);
        }
    }

    template<typename T>
    void NotifyObserver(int what, std::shared_ptr<T> object)
    {
        auto iter = observerHandlerMap_.find(what);
        if (iter == observerHandlerMap_.end()) {
            OHOS::HiviewDFX::HiLog::Info(OBSERVER_LABEL, "NotifyObserver %{public}d not register", what);
            return;
        }
        for (auto handlers : iter->second) {
            OHOS::HiviewDFX::HiLog::Info(OBSERVER_LABEL, "NotifyObserver handlers->SendEvent:%{public}d", what);
            handlers->SendEvent(what, object);
        }
    }

    enum ObserverHandlerId {
        RADIO_STATE_CHANGED = 0,
        RADIO_ON = 1,
        RADIO_AVAIL = 2,
        RADIO_OFF_OR_NOT_AVAIL = 3,
        RADIO_NOT_AVAIL = 4,
        RADIO_CALL_STATE = 5,
        RADIO_NETWORK_STATE = 6,
        RADIO_DATA_CALL_LIST_CHANGED = 7,
        RADIO_IMS_NETWORK_STATE_CHANGED = 8,
        RADIO_ICC_STATUS_CHANGED = 9,
        RADIO_CONNECTED = 10,
        RADIO_ICC_REFRESH = 11,
        RADIO_PCODATA = 12,
        RADIO_GET_SIGNAL_STRENGTH = 13,
        RADIO_GSM_SMS = 14,
        RADIO_SIGNAL_STRENGTH_UPDATE = 15,
        RADIO_SMS_ON_SIM = 16,
        RADIO_SMS_STATUS = 17,
        RADIO_RESTRICTED_STATE = 18,

        // cellcall
        RADIO_DIAL = 19,
        RADIO_REJECT_CALL = 20,
        RADIO_HANDUP_CONNECT = 21,
        RADIO_ACCEPT_CALL = 22,
        RADIO_LAST_CALL_FAIL_CAUSE = 23,
        RADIO_CURRENT_CALLS = 24,

        // Imssms
        RADIO_SEND_IMS_GSM_SMS = 25,
        RADIO_SEND_SMS = 26,
        RADIO_SEND_SMS_EXPECT_MORE = 27,

        // data
        RADIO_POWER = 28,
        RADIO_VOICE_REG_STATE = 29,
        RADIO_DATA_REG_STATE = 30,
        RADIO_OPERATOR = 31,
        RADIO_RIL_SETUP_DATA_CALL = 32,
        RADIO_RIL_IMS_REGISTRATION_STATE = 33,
        RADIO_RIL_DEACTIVATE_DATA_CALL = 34,

        // module internal events
        RADIO_PS_CONNECTION_ATTACHED = 500,
        RADIO_PS_CONNECTION_DETACHED,
        RADIO_SIM_STATE_CHANGE,
        RADIO_SIM_STATE_READY,
        RADIO_IMSI_LOADED_READY,
        RADIO_SIM_RECORDS_LOADED,
    };

private:
    std::unordered_map<int32_t, std::list<std::shared_ptr<AppExecFwk::EventHandler>>> observerHandlerMap_;
};
} // namespace OHOS
#endif // OBSERVER_HANDLER_H
