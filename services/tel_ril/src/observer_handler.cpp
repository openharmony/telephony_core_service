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

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
ObserverHandler::ObserverHandler() {}

ObserverHandler::~ObserverHandler() {}

void ObserverHandler::RegObserver(int32_t what, const std::shared_ptr<AppExecFwk::EventHandler> handler)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = observerHandlerMap_.find(what);
    if (iter != observerHandlerMap_.end()) {
        std::list<std::shared_ptr<OHOS::AppExecFwk::EventHandler>> &handlers = iter->second;
        auto it = find(handlers.begin(), handlers.end(), handler);
        if (it == handlers.end()) {
            handlers.push_back(handler);
        }
        TELEPHONY_LOGI("ObserverHandler RegObserver update callback what: %{public}d, list size: %{public}zu", what,
            handlers.size());
    } else {
        TELEPHONY_LOGI("ObserverHandler RegObserver callback what: %{public}d", what);
        std::list<std::shared_ptr<AppExecFwk::EventHandler>> handlers;
        handlers.push_back(handler);
        observerHandlerMap_.emplace(what, handlers);
    }
}

void ObserverHandler::RemoveAll()
{
    std::lock_guard<std::mutex> lock(mutex_);
    observerHandlerMap_.clear();
}

void ObserverHandler::Remove(int32_t what, const std::shared_ptr<AppExecFwk::EventHandler> handler)
{
    if (handler == nullptr) {
        TELEPHONY_LOGE("ObserverHandler handler==nullptr");
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = observerHandlerMap_.find(what);
    if (iter != observerHandlerMap_.end()) {
        std::list<std::shared_ptr<OHOS::AppExecFwk::EventHandler>> &handlers = iter->second;
        auto it = find(handlers.begin(), handlers.end(), handler);
        if (it != handlers.end()) {
            handlers.erase(it);
        }
        TELEPHONY_LOGI("ObserverHandler Remove handlers list: %{public}zu", handlers.size());
    }
}

void ObserverHandler::NotifyObserver(int32_t what)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = observerHandlerMap_.find(what);
    if (iter == observerHandlerMap_.end()) {
        TELEPHONY_LOGE("ObserverHandler NotifyObserver %{public}d not register", what);
        return;
    }

    for (auto handler : iter->second) {
        TELEPHONY_LOGI("handler->SendEvent:%{public}d", what);
        handler->SendEvent(what);
    }
}
} // namespace Telephony
} // namespace OHOS