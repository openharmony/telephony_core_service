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
#ifndef COMMON_EVENT_PUBLISH_INFO_H
#define COMMON_EVENT_PUBLISH_INFO_H

#include <cstdint>
#include <string>
#include <vector>
#include <new>

#include "parcel.h"

namespace OHOS {
namespace EventFwk {

enum SubscriberType { ALL_SUBSCRIBER_TYPE, SYSTEM_SUBSCRIBER_TYPE };

enum class ValidationRule {
    AND = 1,
    OR = 2,
};

static constexpr uint16_t SUBSCRIBER_FILTER_BUNDLE_INDEX = 1 << 0;
static constexpr uint16_t SUBSCRIBER_FILTER_PERMISSION_INDEX = 1 << 1;
static constexpr uint16_t SUBSCRIBER_FILTER_SUBSCRIBER_TYPE_INDEX = 1 << 2;
static constexpr uint16_t SUBSCRIBER_FILTER_SUBSCRIBER_UID_INDEX = 1 << 3;
static constexpr int32_t UNINITIALIZATED_SUBSCRIBER_TYPE = -1;

class CommonEventPublishInfo : public Parcelable {
public:
    static constexpr int MAX_SUBSCRIBER_UIDS = 3;

    CommonEventPublishInfo()
        : sticky_(false), ordered_(false), subscriberType_(UNINITIALIZATED_SUBSCRIBER_TYPE), rule_(ValidationRule::AND)
    {}

    explicit CommonEventPublishInfo(const CommonEventPublishInfo &info)
        : sticky_(info.sticky_), ordered_(info.ordered_), bundleName_(info.bundleName_),
          subscriberPermissions_(info.subscriberPermissions_), subscriberUids_(info.subscriberUids_),
          subscriberType_(info.subscriberType_), rule_(info.rule_)
    {}

    ~CommonEventPublishInfo() = default;

    void SetSticky(bool sticky)
    {
        sticky_ = sticky;
    }
    bool IsSticky() const
    {
        return sticky_;
    }

    void SetSubscriberPermissions(const std::vector<std::string> &subscriberPermissions)
    {
        subscriberPermissions_ = subscriberPermissions;
    }

    const std::vector<std::string> &GetSubscriberPermissions() const
    {
        return subscriberPermissions_;
    }

    void SetOrdered(bool ordered)
    {
        ordered_ = ordered;
    }
    bool IsOrdered() const
    {
        return ordered_;
    }

    void SetBundleName(const std::string &bundleName)
    {
        bundleName_ = bundleName;
    }
    std::string GetBundleName() const
    {
        return bundleName_;
    }

    void SetSubscriberUid(const std::vector<int32_t> &subscriberUids)
    {
        if (subscriberUids.size() > MAX_SUBSCRIBER_UIDS) {
            subscriberUids_ =
                std::vector<int32_t>(subscriberUids.begin(), subscriberUids.begin() + MAX_SUBSCRIBER_UIDS);
        } else {
            subscriberUids_ = subscriberUids;
        }
    }

    std::vector<int32_t> GetSubscriberUid() const
    {
        return subscriberUids_;
    }

    void SetSubscriberType(const int32_t &subscriberType)
    {
        if (!isSubscriberType(subscriberType)) {
            subscriberType_ = static_cast<int32_t>(SubscriberType::ALL_SUBSCRIBER_TYPE);
        } else {
            subscriberType_ = subscriberType;
        }
    }

    int32_t GetSubscriberType() const
    {
        return subscriberType_;
    }

    void SetValidationRule(const ValidationRule &rule)
    {
        rule_ = rule;
    }
    ValidationRule GetValidationRule() const
    {
        return rule_;
    }

    uint16_t GetFilterSettings() const
    {
        uint16_t filterSettings = 0;
        if (subscriberType_ != UNINITIALIZATED_SUBSCRIBER_TYPE) {
            filterSettings |= SUBSCRIBER_FILTER_SUBSCRIBER_TYPE_INDEX;
        }
        if (!bundleName_.empty()) {
            filterSettings |= SUBSCRIBER_FILTER_BUNDLE_INDEX;
        }
        if (!subscriberPermissions_.empty()) {
            filterSettings |= SUBSCRIBER_FILTER_PERMISSION_INDEX;
        }
        if (!subscriberUids_.empty()) {
            filterSettings |= SUBSCRIBER_FILTER_SUBSCRIBER_UID_INDEX;
        }
        return filterSettings;
    }

    virtual bool Marshalling(Parcel &parcel) const override
    {
        std::vector<std::u16string> permissionVec_;
        for (const auto &perm : subscriberPermissions_) {
            permissionVec_.emplace_back(Str8ToStr16(perm));
        }

        if (!parcel.WriteString16Vector(permissionVec_)) {
            return false;
        }
        if (!parcel.WriteBool(ordered_)) {
            return false;
        }
        if (!parcel.WriteBool(sticky_)) {
            return false;
        }
        if (!parcel.WriteString16(Str8ToStr16(bundleName_))) {
            return false;
        }
        if (!parcel.WriteInt32Vector(subscriberUids_)) {
            return false;
        }
        if (!parcel.WriteInt32(subscriberType_)) {
            return false;
        }
        if (!parcel.WriteInt32(static_cast<int32_t>(rule_))) {
            return false;
        }
        return true;
    }

    static CommonEventPublishInfo *Unmarshalling(Parcel &parcel)
    {
        CommonEventPublishInfo *info = new (std::nothrow) CommonEventPublishInfo();
        if (info == nullptr) {
            return nullptr;
        }
        if (!info->ReadFromParcel(parcel)) {
            delete info;
            return nullptr;
        }
        return info;
    }

private:
    bool ReadFromParcel(Parcel &parcel)
    {
        std::vector<std::u16string> permissionVec_;
        if (!parcel.ReadString16Vector(&permissionVec_)) {
            return false;
        }

        subscriberPermissions_.clear();
        for (const auto &perm : permissionVec_) {
            subscriberPermissions_.emplace_back(Str16ToStr8(perm));
        }

        ordered_ = parcel.ReadBool();
        sticky_ = parcel.ReadBool();
        bundleName_ = Str16ToStr8(parcel.ReadString16());
        if (!parcel.ReadInt32Vector(&subscriberUids_)) {
            return false;
        }
        subscriberType_ = parcel.ReadInt32();

        int32_t rule = parcel.ReadInt32();
        if (rule < static_cast<int32_t>(ValidationRule::AND) || rule > static_cast<int32_t>(ValidationRule::OR)) {
            return false;
        }
        rule_ = static_cast<ValidationRule>(rule);
        return true;
    }

    bool isSubscriberType(int32_t type) const
    {
        if (type == static_cast<int32_t>(SubscriberType::ALL_SUBSCRIBER_TYPE)) {
            return true;
        }
        if (type == static_cast<int32_t>(SubscriberType::SYSTEM_SUBSCRIBER_TYPE)) {
            return true;
        }
        return false;
    }

private:
    bool sticky_;
    bool ordered_;
    std::string bundleName_;
    std::vector<std::string> subscriberPermissions_;
    std::vector<int32_t> subscriberUids_;
    int32_t subscriberType_;
    ValidationRule rule_;
};

}  // namespace EventFwk
}  // namespace OHOS

#endif  // COMMON_EVENT_PUBLISH_INFO_H
