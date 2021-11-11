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
enum SimPhoneBookType { SimPhoneBook_Adn = 1, SimPhoneBook_Fdn = 2 };
class DiallingNumbersInfo : public Parcelable {
public:
    int32_t extRecord_ = 0xff;
    int32_t efid_ = 0;
    int32_t recordNumber_ = 0;
    std::u16string alphaTag_ = u"";
    std::u16string number_ = u"";
    std::vector<std::u16string> emails_;
    std::u16string pin2_ = u"";
    bool ReadFromParcel(Parcel &parcel)
    {
        if (!parcel.ReadInt32(extRecord_)) {
            return false;
        }
        if (!parcel.ReadInt32(efid_)) {
            return false;
        }
        if (!parcel.ReadInt32(recordNumber_)) {
            return false;
        }
        if (!parcel.ReadString16(alphaTag_)) {
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
        if (!parcel.WriteInt32(extRecord_)) {
            return false;
        }
        if (!parcel.WriteInt32(efid_)) {
            return false;
        }
        if (!parcel.WriteInt32(recordNumber_)) {
            return false;
        }
        if (!parcel.WriteString16(alphaTag_)) {
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
        efid_ = efid;
        recordNumber_ = recordNumber;
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
        efid_ = efid;
        recordNumber_ = recordNumber;
        alphaTag_ = alphaTag;
        number_ = number;
        emails_.assign(emails.begin(), emails.end());
    }

    DiallingNumbersInfo(int32_t efid, int32_t recordNumber, std::u16string &alphaTag, std::u16string &number)
    {
        efid_ = efid;
        recordNumber_ = recordNumber;
        alphaTag_ = alphaTag;
        number_ = number;
    }

    virtual ~DiallingNumbersInfo() {}

    std::u16string GetAlphaTag()
    {
        return alphaTag_;
    }

    int32_t GetEfid()
    {
        return efid_;
    }

    int32_t GetRecId()
    {
        return recordNumber_;
    }

    std::u16string GetNumber()
    {
        return number_;
    }

    void SetNumber(std::u16string number)
    {
        number_ = number;
    }

    std::vector<std::u16string> GetEmails()
    {
        return emails_;
    }

    void SetEmails(std::vector<std::u16string> &emails)
    {
        emails_.assign(emails.begin(), emails.end());
    }

    bool IsEmpty()
    {
        return (alphaTag_.empty() && number_.empty() && emails_.empty());
    }

    bool HasExtendedRecord()
    {
        return (extRecord_ != 0) && (extRecord_ != 0xff);
    }
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_DIALLING_NUMBER_INFO_H