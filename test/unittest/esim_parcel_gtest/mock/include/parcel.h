/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef MOCK_OHOS_UTILS_PARCEL_H
#define MOCK_OHOS_UTILS_PARCEL_H

#include <list>
#include <string>

namespace OHOS {
void MockWriteUint32(bool state, std::list<bool> *mockList = nullptr);

void MockWriteInt32(bool state, std::list<bool> *mockList = nullptr);

void MockWriteString16(bool state, std::list<bool> *mockList = nullptr);

void MockWriteBool(bool state, std::list<bool> *mockList = nullptr);

void MockReadUint32(bool state, uint32_t value = 10, std::list<bool> *mockList = nullptr);

void MockReadInt32(bool state, std::list<bool> *mockList = nullptr);

void MockReadString16(bool state, std::list<bool> *mockList = nullptr);

void MockReadBool(bool state, std::list<bool> *mockList = nullptr);

void ResetParcelState();

class Parcelable;
class Parcel {
public:
    Parcel() {}
    virtual ~Parcel() = default;

    bool WriteUint32(uint32_t) const;

    bool WriteInt32(int32_t) const;

    bool WriteString16(const std::u16string&) const;

    bool WriteBool(bool) const;

    bool ReadUint32(uint32_t&) const;

    bool ReadInt32(int32_t&) const;

    bool ReadString16(const std::u16string&) const;

    bool ReadBool(bool&) const;
};

class Parcelable {
public:
    Parcelable() = default;
    virtual ~Parcelable() = default;
    virtual bool Marshalling(Parcel& parcel) const
    {
        return true;
    }
};
} // namespace OHOS
#endif
