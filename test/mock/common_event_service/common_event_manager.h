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

#include "common_event_data.h"
#include "common_event_publish_info.h"
#include "common_event_subscriber.h"

namespace OHOS {
namespace EventFwk {

class CommonEventManager {
public:
    static bool PublishCommonEvent(const CommonEventData &data)
    {
        return true;
    }

    static bool PublishCommonEventAsUser(const CommonEventData &data, const int32_t &userId)
    {
        return true;
    }

    static bool PublishCommonEvent(const CommonEventData &data, const CommonEventPublishInfo &publishInfo)
    {
        return true;
    }

    static int32_t NewPublishCommonEvent(const CommonEventData &data, const CommonEventPublishInfo &publishInfo)
    {
        return 0;
    }

    static bool PublishCommonEventAsUser(
        const CommonEventData &data, const CommonEventPublishInfo &publishInfo, const int32_t &userId)
    {
        return true;
    }

    static int32_t NewPublishCommonEventAsUser(
        const CommonEventData &data, const CommonEventPublishInfo &publishInfo, const int32_t &userId)
    {
        return 0;
    }

    static bool PublishCommonEvent(const CommonEventData &data, const CommonEventPublishInfo &publishInfo,
        const std::shared_ptr<CommonEventSubscriber> &subscriber)
    {
        return true;
    }

    static bool PublishCommonEventAsUser(const CommonEventData &data, const CommonEventPublishInfo &publishInfo,
        const std::shared_ptr<CommonEventSubscriber> &subscriber, const int32_t &userId)
    {
        return true;
    }

    static int32_t NewPublishCommonEventAsUser(const CommonEventData &data, const CommonEventPublishInfo &publishInfo,
        const std::shared_ptr<CommonEventSubscriber> &subscriber, const int32_t &userId)
    {
        return 0;
    }

    static bool PublishCommonEvent(const CommonEventData &data, const CommonEventPublishInfo &publishInfo,
        const std::shared_ptr<CommonEventSubscriber> &subscriber, const uid_t &uid, const int32_t &callerToken)
    {
        return true;
    }

    static bool PublishCommonEventAsUser(const CommonEventData &data, const CommonEventPublishInfo &publishInfo,
        const std::shared_ptr<CommonEventSubscriber> &subscriber, const uid_t &uid, const int32_t &callerToken,
        const int32_t &userId)
    {
        return true;
    }

    static bool SubscribeCommonEvent(const std::shared_ptr<CommonEventSubscriber> &subscriber)
    {
        return true;
    }

    static int32_t NewSubscribeCommonEvent(const std::shared_ptr<CommonEventSubscriber> &subscriber)
    {
        return 0;
    }

    static bool UnSubscribeCommonEvent(const std::shared_ptr<CommonEventSubscriber> &subscriber)
    {
        return true;
    }

    static int32_t NewUnSubscribeCommonEvent(const std::shared_ptr<CommonEventSubscriber> &subscriber)
    {
        return 0;
    }

    static int32_t NewUnSubscribeCommonEventSync(const std::shared_ptr<CommonEventSubscriber> &subscriber)
    {
        return 0;
    }

    static bool GetStickyCommonEvent(const std::string &event, CommonEventData &data)
    {
        return true;
    }

    static bool Freeze(const uid_t &uid)
    {
        return true;
    }

    static bool Unfreeze(const uid_t &uid)
    {
        return true;
    }

    static bool UnfreezeAll()
    {
        return true;
    }

    static int32_t RemoveStickyCommonEvent(const std::string &event)
    {
        return 0;
    }

    static int32_t SetStaticSubscriberState(bool enable)
    {
        return 0;
    }

    static int32_t SetStaticSubscriberState(const std::vector<std::string> &events, bool enable)
    {
        return 0;
    }

    static bool SetFreezeStatus(std::set<int> pidList, bool isFreeze)
    {
        return true;
    }
};

}  // namespace EventFwk
}  // namespace OHOS

#endif  // COMMON_EVENT_MANAGER_H