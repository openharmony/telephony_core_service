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
#ifndef COMMON_EVENT_DATA_H
#define COMMON_EVENT_DATA_H

#include <string>
#include <memory>
#include <new>

#include "parcel.h"
#include "want.h"

namespace OHOS {
namespace EventFwk {

using Want = OHOS::AAFwk::Want;

class CommonEventData : public Parcelable {
public:
    static constexpr int VALUE_NULL = -1;
    static constexpr int VALUE_OBJECT = 1;

    CommonEventData() : code_(0)
    {}

    explicit CommonEventData(const Want &want) : want_(want), code_(0)
    {}

    CommonEventData(const Want &want, const int32_t &code, const std::string &data)
        : want_(want), code_(code), data_(data)
    {}

    ~CommonEventData() = default;

    void SetWant(const Want &want)
    {
        want_ = want;
    }
    const Want &GetWant() const
    {
        return want_;
    }

    void SetCode(const int32_t &code)
    {
        code_ = code;
    }
    int32_t GetCode() const
    {
        return code_;
    }

    void SetData(const std::string &data)
    {
        data_ = data;
    }
    std::string GetData() const
    {
        return data_;
    }

    virtual bool Marshalling(Parcel &parcel) const override
    {
        if (GetData().empty()) {
            if (!parcel.WriteInt32(VALUE_NULL)) {
                return false;
            }
        } else {
            if (!parcel.WriteInt32(VALUE_OBJECT)) {
                return false;
            }
            if (!parcel.WriteString16(Str8ToStr16(GetData()))) {
                return false;
            }
        }

        if (!parcel.WriteInt32(code_)) {
            return false;
        }

        if (!parcel.WriteParcelable(&want_)) {
            return false;
        }

        return true;
    }

    static CommonEventData *Unmarshalling(Parcel &parcel)
    {
        CommonEventData *data = new (std::nothrow) CommonEventData();
        if (data == nullptr) {
            return nullptr;
        }
        if (!data->ReadFromParcel(parcel)) {
            delete data;
            return nullptr;
        }
        return data;
    }

private:
    bool ReadFromParcel(Parcel &parcel)
    {
        int empty = VALUE_NULL;
        if (!parcel.ReadInt32(empty)) {
            return false;
        }

        if (empty == VALUE_OBJECT) {
            SetData(Str16ToStr8(parcel.ReadString16()));
        }

        code_ = parcel.ReadInt32();

        std::unique_ptr<Want> want(parcel.ReadParcelable<Want>());
        if (!want) {
            return false;
        }
        want_ = *want;

        return true;
    }

private:
    Want want_;
    int32_t code_;
    std::string data_;
};

}  // namespace EventFwk
}  // namespace OHOS

#endif  // COMMON_EVENT_DATA_H