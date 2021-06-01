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
#include "observer_handler.h"
#include "telephony_log.h"

namespace OHOS {
ObserverHandler::ObserverHandler() {}

ObserverHandler::~ObserverHandler() {}

void ObserverHandler::RegObserver(int what, const std::shared_ptr<AppExecFwk::EventHandler> handler)
{
    auto iter = observerHandlerMap_.find(what);
    if (iter != observerHandlerMap_.end()) {
        std::list<std::shared_ptr<OHOS::AppExecFwk::EventHandler>> &handlers = iter->second;
        auto it = find(handlers.begin(), handlers.end(), handler);
        if (it == handlers.end()) {
            handlers.push_back(handler);
        }
        TELEPHONY_INFO_LOG("ObserverHandler RegObserver handlers list: %{public}zu", handlers.size());
    } else {
        TELEPHONY_INFO_LOG("ObserverHandler RegObserver callback list %{public}d", what);
        std::list<std::shared_ptr<AppExecFwk::EventHandler>> handlers;
        handlers.push_back(handler);
        observerHandlerMap_.emplace(what, handlers);
    }
}

void ObserverHandler::RemoveAll()
{
    observerHandlerMap_.erase(observerHandlerMap_.begin(), observerHandlerMap_.end());
}

void ObserverHandler::Remove(int what)
{
    observerHandlerMap_.erase(what);
}

void ObserverHandler::NotifyObserver(int what)
{
    auto iter = observerHandlerMap_.find(what);
    if (iter == observerHandlerMap_.end()) {
        TELEPHONY_INFO_LOG("ObserverHandler NotifyObserver %{public}d not register", what);
        return;
    }

    for (auto handlers : iter->second) {
        TELEPHONY_INFO_LOG("handlers->SendEvent:%{public}d", what);
        handlers->SendEvent(what);
    }
}
} // namespace OHOS