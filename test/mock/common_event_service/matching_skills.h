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
#ifndef MATCHING_SKILLS_H
#define MATCHING_SKILLS_H

#include <string>
#include <vector>
#include <algorithm>
#include <new>

#include "parcel.h"
#include "want.h"
#include "string_ex.h"

namespace OHOS {
namespace EventFwk {

using Want = OHOS::AAFwk::Want;

class MatchingSkills : public Parcelable {
public:
    MatchingSkills() = default;

    MatchingSkills(const MatchingSkills &matchingSkills)
        : entities_(matchingSkills.entities_), events_(matchingSkills.events_), schemes_(matchingSkills.schemes_)
    {}

    ~MatchingSkills() = default;

    std::string GetEntity(size_t index) const
    {
        if (index < entities_.size()) {
            return entities_[index];
        }
        return {};
    }

    void AddEntity(const std::string &entity)
    {
        if (!HasEntity(entity)) {
            entities_.emplace_back(entity);
        }
    }

    bool HasEntity(const std::string &entity) const
    {
        return std::find(entities_.cbegin(), entities_.cend(), entity) != entities_.cend();
    }

    void RemoveEntity(const std::string &entity)
    {
        auto it = std::find(entities_.cbegin(), entities_.cend(), entity);
        if (it != entities_.cend()) {
            entities_.erase(it);
        }
    }

    size_t CountEntities() const
    {
        return entities_.size();
    }

    void AddEvent(const std::string &event)
    {
        if (!HasEvent(event)) {
            events_.emplace_back(event);
        }
    }

    size_t CountEvent() const
    {
        return events_.size();
    }

    std::string GetEvent(size_t index) const
    {
        if (index < events_.size()) {
            return events_[index];
        }
        return {};
    }

    std::vector<std::string> GetEvents() const
    {
        return events_;
    }

    void RemoveEvent(const std::string &event)
    {
        auto it = std::find(events_.cbegin(), events_.cend(), event);
        if (it != events_.cend()) {
            events_.erase(it);
        }
    }

    bool HasEvent(const std::string &event) const
    {
        return std::find(events_.cbegin(), events_.cend(), event) != events_.cend();
    }

    std::string GetScheme(size_t index) const
    {
        if (index < schemes_.size()) {
            return schemes_[index];
        }
        return {};
    }

    void AddScheme(const std::string &scheme)
    {
        if (!HasScheme(scheme)) {
            schemes_.emplace_back(scheme);
        }
    }

    bool HasScheme(const std::string &scheme) const
    {
        return std::find(schemes_.begin(), schemes_.end(), scheme) != schemes_.end();
    }

    void RemoveScheme(const std::string &scheme)
    {
        auto it = std::find(schemes_.cbegin(), schemes_.cend(), scheme);
        if (it != schemes_.cend()) {
            schemes_.erase(it);
        }
    }

    size_t CountSchemes() const
    {
        return schemes_.size();
    }

    bool Match(const Want &want) const
    {
        return MatchEvent(want.GetAction()) && MatchEntity(want.GetEntities()) && MatchScheme(want.GetScheme());
    }

    bool Marshalling(Parcel &parcel) const override
    {
        return WriteVector(entities_, parcel) && WriteVector(events_, parcel) && WriteVector(schemes_, parcel);
    }

    static MatchingSkills *Unmarshalling(Parcel &parcel)
    {
        MatchingSkills *matchingSkills = new (std::nothrow) MatchingSkills();
        if (!matchingSkills || !matchingSkills->ReadFromParcel(parcel)) {
            delete matchingSkills;
            return nullptr;
        }
        return matchingSkills;
    }

private:
    bool WriteVectorInfo(Parcel &parcel, std::vector<std::u16string> vectorInfo) const
    {
        if (vectorInfo.empty()) {
            return parcel.WriteInt32(VALUE_NULL);
        } else if (!parcel.WriteInt32(VALUE_OBJECT)) {
            return false;
        }
        return parcel.WriteString16Vector(vectorInfo);
    }

    bool WriteVector(const std::vector<std::string> &vec, Parcel &parcel) const
    {
        std::vector<std::u16string> vec16;
        for (const auto &str : vec) {
            vec16.emplace_back(Str8ToStr16(str));
        }
        return WriteVectorInfo(parcel, vec16);
    }

    bool ReadFromParcel(Parcel &parcel)
    {
        return ReadVectorFromParcel(parcel, entities_) && ReadVectorFromParcel(parcel, events_) &&
               ReadVectorFromParcel(parcel, schemes_);
    }

    bool ReadVectorFromParcel(Parcel &parcel, std::vector<std::string> &vec)
    {
        std::vector<std::u16string> vec16;
        int32_t empty = VALUE_NULL;
        if (!parcel.ReadInt32(empty))
            return false;
        if (empty == VALUE_OBJECT && !parcel.ReadString16Vector(&vec16))
            return false;
        vec.clear();
        for (auto &str16 : vec16)
            vec.emplace_back(Str16ToStr8(str16));
        return true;
    }

    bool MatchEvent(const std::string &event) const
    {
        return !event.empty() && HasEvent(event);
    }

    bool MatchEntity(const std::vector<std::string> &entities) const
    {
        if (entities.empty()) {
            return true;
        }
        for (const auto &e : entities) {
            if (!HasEntity(e)) {
                return false;
            }
        }
        return true;
    }

    bool MatchScheme(const std::string &scheme) const
    {
        if (!schemes_.empty()) {
            return HasScheme(scheme);
        }

        return scheme.empty();
    }

    std::string ToString() const
    {
        std::string result;
        AppendVectorToString("Events", events_, result);
        AppendVectorToString("Schemes", schemes_, result);
        AppendVectorToString("Entities", entities_, result);
        return result;
    }

    void AppendVectorToString(const std::string &label, const std::vector<std::string> &vec, std::string &out) const
    {
        if (!vec.empty()) {
            out.append(" ").append(label).append(": ").append(vec[0]);
            for (size_t i = 1; i < vec.size(); ++i) {
                out.append(",").append(vec[i]);
            }
        }
    }

private:
    std::vector<std::string> entities_;
    std::vector<std::string> events_;
    std::vector<std::string> schemes_;
    static constexpr int32_t VALUE_NULL = -1;
    static constexpr int32_t VALUE_OBJECT = 1;
};

}  // namespace EventFwk
}  // namespace OHOS

#endif  // MATCHING_SKILLS_H