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
#ifndef COMMON_EVENT_SUBSCRIBE_INFO_H
#define COMMON_EVENT_SUBSCRIBE_INFO_H

#include <string>
#include <new>

#include "matching_skills.h"
#include "parcel.h"
#include "common_event_constant.h"

namespace OHOS {
namespace EventFwk {

class CommonEventSubscribeInfo : public Parcelable {
public:
    enum ThreadMode {
        HANDLER,
        POST,
        ASYNC,
        BACKGROUND,
        COMMON,
    };

    CommonEventSubscribeInfo(const MatchingSkills &matchingSkills)
        : matchingSkills_(matchingSkills), priority_(0), userId_(UNDEFINED_USER), threadMode_(ASYNC), publisherUid_(0)
    {}

    CommonEventSubscribeInfo() : priority_(0), userId_(UNDEFINED_USER), threadMode_(ASYNC), publisherUid_(0)
    {}

    CommonEventSubscribeInfo(const CommonEventSubscribeInfo &other)
        : matchingSkills_(other.matchingSkills_), priority_(other.priority_), userId_(other.userId_),
          permission_(other.permission_), deviceId_(other.deviceId_), threadMode_(other.threadMode_),
          publisherBundleName_(other.publisherBundleName_), publisherUid_(other.publisherUid_)
    {}

    ~CommonEventSubscribeInfo() = default;

    void SetPriority(const int32_t &priority)
    {
        priority_ = priority;
    }
    int32_t GetPriority() const
    {
        return priority_;
    }

    void SetUserId(const int32_t &userId)
    {
        userId_ = userId;
    }
    int32_t GetUserId() const
    {
        return userId_;
    }

    void SetPermission(const std::string &permission)
    {
        permission_ = permission;
    }
    std::string GetPermission() const
    {
        return permission_;
    }

    void SetThreadMode(ThreadMode threadMode)
    {
        threadMode_ = threadMode;
    }
    ThreadMode GetThreadMode() const
    {
        return threadMode_;
    }

    void SetDeviceId(const std::string &deviceId)
    {
        deviceId_ = deviceId;
    }
    std::string GetDeviceId() const
    {
        return deviceId_;
    }

    const MatchingSkills &GetMatchingSkills() const
    {
        return matchingSkills_;
    }

    void SetPublisherBundleName(const std::string &publisherBundleName)
    {
        publisherBundleName_ = publisherBundleName;
    }
    std::string GetPublisherBundleName() const
    {
        return publisherBundleName_;
    }

    void SetPublisherUid(int32_t publisherUid)
    {
        publisherUid_ = publisherUid;
    }
    int32_t GetPublisherUid() const
    {
        return publisherUid_;
    }

    bool Marshalling(Parcel &parcel) const override
    {
        if (!parcel.WriteString16(Str8ToStr16(permission_))) {
            return false;
        }
        if (!parcel.WriteInt32(priority_)) {
            return false;
        }
        if (!parcel.WriteInt32(userId_)) {
            return false;
        }
        if (!parcel.WriteUint32(threadMode_)) {
            return false;
        }
        if (!parcel.WriteString16(Str8ToStr16(deviceId_))) {
            return false;
        }
        if (!parcel.WriteParcelable(&matchingSkills_)) {
            return false;
        }
        if (!parcel.WriteString(publisherBundleName_)) {
            return false;
        }
        if (!parcel.WriteInt32(publisherUid_)) {
            return false;
        }
        return true;
    }

    static CommonEventSubscribeInfo *Unmarshalling(Parcel &parcel)
    {
        CommonEventSubscribeInfo *info = new (std::nothrow) CommonEventSubscribeInfo();
        if (!info || !info->ReadFromParcel(parcel)) {
            delete info;
            return nullptr;
        }
        return info;
    }

private:
    bool ReadFromParcel(Parcel &parcel)
    {
        permission_ = Str16ToStr8(parcel.ReadString16());
        priority_ = parcel.ReadInt32();
        userId_ = parcel.ReadInt32();
        threadMode_ = static_cast<ThreadMode>(parcel.ReadUint32());
        deviceId_ = Str16ToStr8(parcel.ReadString16());

        auto skills = parcel.ReadParcelable<MatchingSkills>();
        if (skills) {
            matchingSkills_ = *skills;
            delete skills;
        } else {
            return false;
        }

        publisherBundleName_ = parcel.ReadString();
        publisherUid_ = parcel.ReadInt32();
        return true;
    }

private:
    MatchingSkills matchingSkills_;
    int32_t priority_;
    int32_t userId_;
    std::string permission_;
    std::string deviceId_;
    ThreadMode threadMode_;
    std::string publisherBundleName_;
    int32_t publisherUid_;
};

}  // namespace EventFwk
}  // namespace OHOS

#endif  // COMMON_EVENT_SUBSCRIBE_INFO_H