/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include "vcard_phone_data.h"

#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {

int32_t VCardPhoneData::BuildValuesBucket(OHOS::DataShare::DataShareValuesBucket &valuesBucket)
{
    valuesBucket.Put(ContactData::TYPE_ID, TypeId::PHONE);
    valuesBucket.Put(ContactData::DETAIL_INFO, number_);
    valuesBucket.Put(ContactData::LABEL_ID, labelId_);
    valuesBucket.Put(ContactData::LABEL_NAME, labelName_);
    return TELEPHONY_SUCCESS;
}

int32_t VCardPhoneData::BuildData(std::shared_ptr<DataShare::DataShareResultSet> resultSet)
{
    if (resultSet == nullptr) {
        return TELEPHONY_ERROR;
    }
    int32_t index;
    resultSet->GetColumnIndex(ContactData::DETAIL_INFO, index);
    resultSet->GetString(index, number_);
    resultSet->GetColumnIndex(ContactData::LABEL_NAME, index);
    resultSet->GetString(index, labelName_);
    resultSet->GetColumnIndex(ContactData::LABEL_ID, index);
    resultSet->GetString(index, labelId_);
    return TELEPHONY_SUCCESS;
}

void VCardPhoneData::InitPhoneData(std::string data, int32_t type, std::string label, bool isPrimary)
{
    number_ = data;
    labelId_ = std::to_string(type);
    labelName_ = label;
}

std::string VCardPhoneData::GetNumber()
{
    return number_;
}

void VCardPhoneData::SetNumber(const std::string &number)
{
    number_ = number;
}

std::string VCardPhoneData::GetLabelId()
{
    return labelId_;
}

void VCardPhoneData::SetLabelId(const std::string &labelId)
{
    labelId_ = labelId;
}

std::string VCardPhoneData::GetLabelName()
{
    return labelName_;
}

void VCardPhoneData::SetLabelName(const std::string &labelName)
{
    labelName_ = labelName;
}

int32_t VCardPhoneData::GetType()
{
    return type_;
}

void VCardPhoneData::SetType(int32_t type)
{
    type_ = type;
}

} // namespace Telephony
} // namespace OHOS
