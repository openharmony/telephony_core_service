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
#ifndef COMMON_EVENT_MANAGER_H
#define COMMON_EVENT_MANAGER_H

#include <set>
#include <vector>
#include <string>
#include <gmock/gmock.h>

#include "common_event_data.h"
#include "common_event_publish_info.h"
#include "common_event_subscriber.h"

namespace OHOS {
namespace EventFwk {

class ICommonEventManager {
public:
    virtual ~ICommonEventManager() = default;

    virtual bool PublishCommonEvent(const CommonEventData &data) = 0;
    virtual bool PublishCommonEventAsUser(const CommonEventData &data, const int32_t &userId) = 0;
    virtual bool PublishCommonEvent(const CommonEventData &data, const CommonEventPublishInfo &publishInfo) = 0;
    virtual int32_t NewPublishCommonEvent(const CommonEventData &data, const CommonEventPublishInfo &publishInfo) = 0;
    virtual bool PublishCommonEventAsUser(
        const CommonEventData &data, const CommonEventPublishInfo &publishInfo, const int32_t &userId) = 0;
    virtual int32_t NewPublishCommonEventAsUser(
        const CommonEventData &data, const CommonEventPublishInfo &publishInfo, const int32_t &userId) = 0;
    virtual bool PublishCommonEvent(const CommonEventData &data, const CommonEventPublishInfo &publishInfo,
        const std::shared_ptr<CommonEventSubscriber> &subscriber) = 0;
    virtual bool PublishCommonEventAsUser(const CommonEventData &data, const CommonEventPublishInfo &publishInfo,
        const std::shared_ptr<CommonEventSubscriber> &subscriber, const int32_t &userId) = 0;
    virtual int32_t NewPublishCommonEventAsUser(const CommonEventData &data, const CommonEventPublishInfo &publishInfo,
        const std::shared_ptr<CommonEventSubscriber> &subscriber, const int32_t &userId) = 0;
    virtual bool PublishCommonEvent(const CommonEventData &data, const CommonEventPublishInfo &publishInfo,
        const std::shared_ptr<CommonEventSubscriber> &subscriber, const uid_t &uid, const int32_t &callerToken) = 0;
    virtual bool PublishCommonEventAsUser(const CommonEventData &data, const CommonEventPublishInfo &publishInfo,
        const std::shared_ptr<CommonEventSubscriber> &subscriber, const uid_t &uid, const int32_t &callerToken,
        const int32_t &userId) = 0;
    virtual bool SubscribeCommonEvent(const std::shared_ptr<CommonEventSubscriber> &subscriber) = 0;
    virtual int32_t NewSubscribeCommonEvent(const std::shared_ptr<CommonEventSubscriber> &subscriber) = 0;
    virtual bool UnSubscribeCommonEvent(const std::shared_ptr<CommonEventSubscriber> &subscriber) = 0;
    virtual int32_t NewUnSubscribeCommonEvent(const std::shared_ptr<CommonEventSubscriber> &subscriber) = 0;
    virtual int32_t NewUnSubscribeCommonEventSync(const std::shared_ptr<CommonEventSubscriber> &subscriber) = 0;
    virtual bool GetStickyCommonEvent(const std::string &event, CommonEventData &data) = 0;
    virtual bool Freeze(const uid_t &uid) = 0;
    virtual bool Unfreeze(const uid_t &uid) = 0;
    virtual bool UnfreezeAll() = 0;
    virtual int32_t RemoveStickyCommonEvent(const std::string &event) = 0;
    virtual int32_t SetStaticSubscriberState(bool enable) = 0;
    virtual int32_t SetStaticSubscriberState(const std::vector<std::string> &events, bool enable) = 0;
    virtual bool SetFreezeStatus(std::set<int> pidList, bool isFreeze) = 0;
};

class MockCommonEventManager {
public:
    MOCK_METHOD(bool, PublishCommonEvent, (const CommonEventData &data), ());
    MOCK_METHOD(bool, PublishCommonEventAsUser, (const CommonEventData &data, const int32_t &userId), ());
    MOCK_METHOD(bool, PublishCommonEvent, (const CommonEventData &data, const CommonEventPublishInfo &publishInfo), ());
    MOCK_METHOD(
        int32_t, NewPublishCommonEvent, (const CommonEventData &data, const CommonEventPublishInfo &publishInfo), ());
    MOCK_METHOD(bool, PublishCommonEventAsUser,
        (const CommonEventData &data, const CommonEventPublishInfo &publishInfo, const int32_t &userId), ());
    MOCK_METHOD(int32_t, NewPublishCommonEventAsUser,
        (const CommonEventData &data, const CommonEventPublishInfo &publishInfo, const int32_t &userId), ());
    MOCK_METHOD(bool, PublishCommonEvent,
        (const CommonEventData &data, const CommonEventPublishInfo &publishInfo,
            const std::shared_ptr<CommonEventSubscriber> &subscriber),
        ());
    MOCK_METHOD(bool, PublishCommonEventAsUser,
        (const CommonEventData &data, const CommonEventPublishInfo &publishInfo,
            const std::shared_ptr<CommonEventSubscriber> &subscriber, const int32_t &userId),
        ());
    MOCK_METHOD(int32_t, NewPublishCommonEventAsUser,
        (const CommonEventData &data, const CommonEventPublishInfo &publishInfo,
            const std::shared_ptr<CommonEventSubscriber> &subscriber, const int32_t &userId),
        ());
    MOCK_METHOD(bool, PublishCommonEvent,
        (const CommonEventData &data, const CommonEventPublishInfo &publishInfo,
            const std::shared_ptr<CommonEventSubscriber> &subscriber, const uid_t &uid, const int32_t &callerToken),
        ());
    MOCK_METHOD(bool, PublishCommonEventAsUser,
        (const CommonEventData &data, const CommonEventPublishInfo &publishInfo,
            const std::shared_ptr<CommonEventSubscriber> &subscriber, const uid_t &uid, const int32_t &callerToken,
            const int32_t &userId),
        ());
    MOCK_METHOD(bool, SubscribeCommonEvent, (const std::shared_ptr<CommonEventSubscriber> &subscriber), ());
    MOCK_METHOD(int32_t, NewSubscribeCommonEvent, (const std::shared_ptr<CommonEventSubscriber> &subscriber), ());
    MOCK_METHOD(bool, UnSubscribeCommonEvent, (const std::shared_ptr<CommonEventSubscriber> &subscriber), ());
    MOCK_METHOD(int32_t, NewUnSubscribeCommonEvent, (const std::shared_ptr<CommonEventSubscriber> &subscriber), ());
    MOCK_METHOD(int32_t, NewUnSubscribeCommonEventSync, (const std::shared_ptr<CommonEventSubscriber> &subscriber), ());
    MOCK_METHOD(bool, GetStickyCommonEvent, (const std::string &event, CommonEventData &data), ());
    MOCK_METHOD(bool, Freeze, (const uid_t &uid), ());
    MOCK_METHOD(bool, Unfreeze, (const uid_t &uid), ());
    MOCK_METHOD(bool, UnfreezeAll, (), ());
    MOCK_METHOD(int32_t, RemoveStickyCommonEvent, (const std::string &event), ());
    MOCK_METHOD(int32_t, SetStaticSubscriberState, (bool enable), ());
    MOCK_METHOD(int32_t, SetStaticSubscriberState, (const std::vector<std::string> &events, bool enable), ());
    MOCK_METHOD(bool, SetFreezeStatus, (std::set<int> pidList, bool isFreeze), ());
};

class CommonEventManager {
public:
    // 获取 / 设置静态 mock 单例
    static std::shared_ptr<MockCommonEventManager> GetMock()
    {
        return mockInstance_;
    }

    static void SetMock(std::shared_ptr<MockCommonEventManager> mock)
    {
        mockInstance_ = mock;
    }

    static bool PublishCommonEvent(const CommonEventData &data)
    {
        if (mockInstance_ != nullptr) {
            return mockInstance_->PublishCommonEvent(data);
        }
        return true;
    }

    static bool PublishCommonEventAsUser(const CommonEventData &data, const int32_t &userId)
    {
        if (mockInstance_ != nullptr) {
            return mockInstance_->PublishCommonEventAsUser(data, userId);
        }
        return true;
    }

    static bool PublishCommonEvent(const CommonEventData &data, const CommonEventPublishInfo &publishInfo)
    {
        if (mockInstance_ != nullptr) {
            return mockInstance_->PublishCommonEvent(data, publishInfo);
        }
        return true;
    }

    static int32_t NewPublishCommonEvent(const CommonEventData &data, const CommonEventPublishInfo &publishInfo)
    {
        if (mockInstance_ != nullptr) {
            return mockInstance_->NewPublishCommonEvent(data, publishInfo);
        }
        return 0;
    }

    static bool PublishCommonEventAsUser(
        const CommonEventData &data, const CommonEventPublishInfo &publishInfo, const int32_t &userId)
    {
        if (mockInstance_ != nullptr) {
            return mockInstance_->PublishCommonEventAsUser(data, publishInfo, userId);
        }
        return true;
    }

    static int32_t NewPublishCommonEventAsUser(
        const CommonEventData &data, const CommonEventPublishInfo &publishInfo, const int32_t &userId)
    {
        if (mockInstance_ != nullptr) {
            return mockInstance_->NewPublishCommonEventAsUser(data, publishInfo, userId);
        }
        return 0;
    }

    static bool PublishCommonEvent(const CommonEventData &data, const CommonEventPublishInfo &publishInfo,
        const std::shared_ptr<CommonEventSubscriber> &subscriber)
    {
        if (mockInstance_ != nullptr) {
            return mockInstance_->PublishCommonEvent(data, publishInfo, subscriber);
        }
        return true;
    }

    static bool PublishCommonEventAsUser(const CommonEventData &data, const CommonEventPublishInfo &publishInfo,
        const std::shared_ptr<CommonEventSubscriber> &subscriber, const int32_t &userId)
    {
        if (mockInstance_ != nullptr) {
            return mockInstance_->PublishCommonEventAsUser(data, publishInfo, subscriber, userId);
        }
        return true;
    }

    static int32_t NewPublishCommonEventAsUser(const CommonEventData &data, const CommonEventPublishInfo &publishInfo,
        const std::shared_ptr<CommonEventSubscriber> &subscriber, const int32_t &userId)
    {
        if (mockInstance_ != nullptr) {
            return mockInstance_->NewPublishCommonEventAsUser(data, publishInfo, subscriber, userId);
        }
        return 0;
    }

    static bool PublishCommonEvent(const CommonEventData &data, const CommonEventPublishInfo &publishInfo,
        const std::shared_ptr<CommonEventSubscriber> &subscriber, const uid_t &uid, const int32_t &callerToken)
    {
        if (mockInstance_ != nullptr) {
            return mockInstance_->PublishCommonEvent(data, publishInfo, subscriber, uid, callerToken);
        }
        return true;
    }

    static bool PublishCommonEventAsUser(const CommonEventData &data, const CommonEventPublishInfo &publishInfo,
        const std::shared_ptr<CommonEventSubscriber> &subscriber, const uid_t &uid, const int32_t &callerToken,
        const int32_t &userId)
    {
        if (mockInstance_ != nullptr) {
            return mockInstance_->PublishCommonEventAsUser(data, publishInfo, subscriber, uid, callerToken, userId);
        }
        return true;
    }

    static bool SubscribeCommonEvent(const std::shared_ptr<CommonEventSubscriber> &subscriber)
    {
        if (mockInstance_ != nullptr) {
            return mockInstance_->SubscribeCommonEvent(subscriber);
        }
        return true;
    }

    static int32_t NewSubscribeCommonEvent(const std::shared_ptr<CommonEventSubscriber> &subscriber)
    {
        if (mockInstance_ != nullptr) {
            return mockInstance_->NewSubscribeCommonEvent(subscriber);
        }
        return 0;
    }

    static bool UnSubscribeCommonEvent(const std::shared_ptr<CommonEventSubscriber> &subscriber)
    {
        if (mockInstance_ != nullptr) {
            return mockInstance_->UnSubscribeCommonEvent(subscriber);
        }
        return true;
    }

    static int32_t NewUnSubscribeCommonEvent(const std::shared_ptr<CommonEventSubscriber> &subscriber)
    {
        if (mockInstance_ != nullptr) {
            return mockInstance_->NewUnSubscribeCommonEvent(subscriber);
        }
        return 0;
    }

    static int32_t NewUnSubscribeCommonEventSync(const std::shared_ptr<CommonEventSubscriber> &subscriber)
    {
        if (mockInstance_ != nullptr) {
            return mockInstance_->NewUnSubscribeCommonEventSync(subscriber);
        }
        return 0;
    }

    static bool GetStickyCommonEvent(const std::string &event, CommonEventData &data)
    {
        if (mockInstance_ != nullptr) {
            return mockInstance_->GetStickyCommonEvent(event, data);
        }
        return true;
    }

    static bool Freeze(const uid_t &uid)
    {
        if (mockInstance_ != nullptr) {
            return mockInstance_->Freeze(uid);
        }
        return true;
    }

    static bool Unfreeze(const uid_t &uid)
    {
        if (mockInstance_ != nullptr) {
            return mockInstance_->Unfreeze(uid);
        }
        return true;
    }

    static bool UnfreezeAll()
    {
        if (mockInstance_ != nullptr) {
            return mockInstance_->UnfreezeAll();
        }
        return true;
    }

    static int32_t RemoveStickyCommonEvent(const std::string &event)
    {
        if (mockInstance_ != nullptr) {
            return mockInstance_->RemoveStickyCommonEvent(event);
        }
        return 0;
    }

    static int32_t SetStaticSubscriberState(bool enable)
    {
        if (mockInstance_ != nullptr) {
            return mockInstance_->SetStaticSubscriberState(enable);
        }
        return 0;
    }

    static int32_t SetStaticSubscriberState(const std::vector<std::string> &events, bool enable)
    {
        if (mockInstance_ != nullptr) {
            return mockInstance_->SetStaticSubscriberState(events, enable);
        }
        return 0;
    }

    static bool SetFreezeStatus(std::set<int> pidList, bool isFreeze)
    {
        if (mockInstance_ != nullptr) {
            return mockInstance_->SetFreezeStatus(pidList, isFreeze);
        }
        return true;
    }

private:
    inline static std::shared_ptr<MockCommonEventManager> mockInstance_ = nullptr;
};

}  // namespace EventFwk
}  // namespace OHOS

#endif  // COMMON_EVENT_MANAGER_H