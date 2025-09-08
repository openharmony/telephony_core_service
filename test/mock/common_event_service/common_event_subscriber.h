/*
 * Copyright (C) 2025-2025 Huawei Device Co., Ltd.
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
#ifndef COMMON_EVENT_SUBSCRIBER_H
#define COMMON_EVENT_SUBSCRIBER_H

#include <memory>
#include <string>

#include "async_common_event_result.h"
#include "common_event_data.h"
#include "common_event_subscribe_info.h"

namespace OHOS {
namespace EventFwk {

class CommonEventSubscriber {
public:
    CommonEventSubscriber() : result_(nullptr)
    {}

    explicit CommonEventSubscriber(const CommonEventSubscribeInfo &subscribeInfo)
        : subscribeInfo_(subscribeInfo), result_(nullptr)
    {}

    virtual ~CommonEventSubscriber() = default;

    virtual void OnReceiveEvent(const CommonEventData &data) = 0;

    const CommonEventSubscribeInfo &GetSubscribeInfo() const
    {
        return subscribeInfo_;
    }

    bool SetCode(const int32_t &code)
    {
        if (!CheckSynchronous()) {
            return false;
        }
        return result_->SetCode(code);
    }

    int32_t GetCode() const
    {
        if (!CheckSynchronous()) {
            return 0;
        }
        return result_->GetCode();
    }

    bool SetData(const std::string &data)
    {
        if (!CheckSynchronous()) {
            return false;
        }
        return result_->SetData(data);
    }

    std::string GetData() const
    {
        if (!CheckSynchronous()) {
            return {};
        }
        return result_->GetData();
    }

    bool SetCodeAndData(const int32_t &code, const std::string &data)
    {
        if (!CheckSynchronous()) {
            return false;
        }
        return result_->SetCodeAndData(code, data);
    }

    bool AbortCommonEvent()
    {
        if (!CheckSynchronous()) {
            return false;
        }
        return result_->AbortCommonEvent();
    }

    bool ClearAbortCommonEvent()
    {
        if (!CheckSynchronous()) {
            return false;
        }
        return result_->ClearAbortCommonEvent();
    }

    bool GetAbortCommonEvent() const
    {
        if (!CheckSynchronous()) {
            return false;
        }
        return result_->GetAbortCommonEvent();
    }

    std::shared_ptr<AsyncCommonEventResult> GoAsyncCommonEvent()
    {
        std::shared_ptr<AsyncCommonEventResult> res = result_;
        result_ = nullptr;
        return res;
    }

    bool IsOrderedCommonEvent() const
    {
        return (result_ != nullptr) ? result_->IsOrderedCommonEvent() : false;
    }

    bool IsStickyCommonEvent() const
    {
        return (result_ != nullptr) ? result_->IsStickyCommonEvent() : false;
    }

private:
    bool SetAsyncCommonEventResult(const std::shared_ptr<AsyncCommonEventResult> &result)
    {
        result_ = result;
        return true;
    }

    std::shared_ptr<AsyncCommonEventResult> GetAsyncCommonEventResult()
    {
        return result_;
    }

    bool CheckSynchronous() const
    {
        if (!result_) {
            return false;
        }
        return result_->CheckSynchronous();
    }

private:
    friend class CommonEventListener;

    CommonEventSubscribeInfo subscribeInfo_;
    std::shared_ptr<AsyncCommonEventResult> result_;
};

}  // namespace EventFwk
}  // namespace OHOS

#endif  // COMMON_EVENT_SUBSCRIBER_H