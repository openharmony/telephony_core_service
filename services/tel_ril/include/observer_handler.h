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

#include <mutex>
#include <unordered_map>

#include "event_handler.h"
#include "tel_event_handler.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class ObserverHandler {
public:
    ObserverHandler();

    virtual ~ObserverHandler();

    void RegObserver(int32_t what, const std::shared_ptr<AppExecFwk::EventHandler> handler);

    void RegUniqueObserver(int32_t what, const std::shared_ptr<AppExecFwk::EventHandler> handler);

    void Remove(int32_t what, const std::shared_ptr<AppExecFwk::EventHandler> handler);

    void RemoveAll();

    void NotifyObserver(int32_t what);

    void NotifyObserver(int32_t what, int64_t param)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto iter = observerHandlerMap_.find(what);
        if (iter == observerHandlerMap_.end()) {
            TELEPHONY_LOGE("ObserverHandler NotifyObserver %{public}d not register", what);
            return;
        }

        for (auto handlers : iter->second) {
            TelEventHandler::SendTelEvent(handlers, what, param, 0);
        }
    }

    template<typename T>
    void NotifyObserver(int32_t what, std::shared_ptr<T> object)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto iter = observerHandlerMap_.find(what);
        if (iter == observerHandlerMap_.end()) {
            TELEPHONY_LOGE("ObserverHandler NotifyObserver %{public}d not register", what);
            return;
        }
        for (auto handlers : iter->second) {
            TelEventHandler::SendTelEvent(handlers, what, object);
        }
    }

private:
    std::unordered_map<int32_t, std::list<std::shared_ptr<AppExecFwk::EventHandler>>> observerHandlerMap_;
    std::mutex mutex_;
};
} // namespace Telephony
} // namespace OHOS
#endif // OBSERVER_HANDLER_H
