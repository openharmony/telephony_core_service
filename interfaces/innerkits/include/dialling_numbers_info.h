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

#ifndef OHOS_DIALLING_NUMBER_INFO_H
#define OHOS_DIALLING_NUMBER_INFO_H

#include <memory>
#include <string>
#include <vector>
#include "parcel.h"

namespace OHOS {
namespace Telephony {
class DiallingNumbersInfo : public Parcelable {
public:
    static const int SIM_ADN = 1;
    static const int SIM_FDN = 2;
    int32_t elementaryFileId_ = 0;
    int32_t index_ = 0;
    std::u16string name_ = u"";
    std::u16string number_ = u"";
    std::vector<std::u16string> emails_;
    std::u16string pin2_ = u"";
    bool ReadFromParcel(Parcel &parcel)
    {
        if (!parcel.ReadInt32(elementaryFileId_)) {
            return false;
        }
        if (!parcel.ReadInt32(index_)) {
            return false;
        }
        if (!parcel.ReadString16(name_)) {
            return false;
        }
        if (!parcel.ReadString16(number_)) {
            return false;
        }
        if (!parcel.ReadString16(pin2_)) {
            return false;
        }
        if (!parcel.ReadString16Vector(&emails_)) {
            return false;
        }
        return true;
    }

    virtual bool Marshalling(Parcel &parcel) const
    {
        if (!parcel.WriteInt32(elementaryFileId_)) {
            return false;
        }
        if (!parcel.WriteInt32(index_)) {
            return false;
        }
        if (!parcel.WriteString16(name_)) {
            return false;
        }
        if (!parcel.WriteString16(number_)) {
            return false;
        }
        if (!parcel.WriteString16(pin2_)) {
            return false;
        }
        if (!parcel.WriteString16Vector(emails_)) {
            return false;
        }
        return true;
    }

    static std::shared_ptr<DiallingNumbersInfo> UnMarshalling(Parcel &parcel)
    {
        std::shared_ptr<DiallingNumbersInfo> param = std::make_shared<DiallingNumbersInfo>();
        if (param == nullptr) {
            return nullptr;
        }
        if (!param->ReadFromParcel(parcel)) {
            return nullptr;
        }
        return param;
    }

    DiallingNumbersInfo() {}

    DiallingNumbersInfo(int32_t efid, int32_t recordNumber)
    {
        elementaryFileId_ = efid;
        index_ = recordNumber;
    }

    DiallingNumbersInfo(std::u16string &alphaTag, std::u16string &number)
    {
        DiallingNumbersInfo(0, 0, alphaTag, number);
    }

    DiallingNumbersInfo(std::u16string alphaTag, std::u16string number, std::vector<std::u16string> &emails)
    {
        DiallingNumbersInfo(0, 0, alphaTag, number, emails);
    }

    DiallingNumbersInfo(int32_t efid, int32_t recordNumber, std::u16string alphaTag, std::u16string number,
        std::vector<std::u16string> &emails)
    {
        elementaryFileId_ = efid;
        index_ = recordNumber;
        name_ = alphaTag;
        number_ = number;
        emails_.assign(emails.begin(), emails.end());
    }

    DiallingNumbersInfo(int32_t efid, int32_t recordNumber, std::u16string &alphaTag, std::u16string &number)
    {
        elementaryFileId_ = efid;
        index_ = recordNumber;
        name_ = alphaTag;
        number_ = number;
    }

    virtual ~DiallingNumbersInfo() {}

    std::u16string GetName()
    {
        return name_;
    }

    int32_t GetFileId()
    {
        return elementaryFileId_;
    }

    int32_t GetIndex()
    {
        return index_;
    }

    std::u16string GetNumber()
    {
        return number_;
    }

    void UpdateNumber(std::u16string number)
    {
        number_ = number;
    }

    std::vector<std::u16string> GetEmails()
    {
        return emails_;
    }

    void UpdateEmails(std::vector<std::u16string> &emails)
    {
        emails_.assign(emails.begin(), emails.end());
    }

    bool IsEmpty()
    {
        return (name_.empty() && number_.empty() && emails_.empty());
    }
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_DIALLING_NUMBER_INFO_H