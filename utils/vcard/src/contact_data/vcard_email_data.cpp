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
#include "vcard_email_data.h"

#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {

int32_t VCardEmailData::BuildValuesBucket(OHOS::DataShare::DataShareValuesBucket &valuesBucket)
{
    valuesBucket.Put(ContactData::TYPE_ID, TypeId::EMAIL);
    valuesBucket.Put(ContactData::DETAIL_INFO, address_);
    valuesBucket.Put(ContactData::LABEL_ID, labelId_);
    valuesBucket.Put(ContactData::LABEL_NAME, labelName_);
    valuesBucket.Put(ContactData::ALIAS_DETAIL_INFO_KEY, displayName_);
    return TELEPHONY_SUCCESS;
}

int32_t VCardEmailData::BuildData(std::shared_ptr<DataShare::DataShareResultSet> resultSet)
{
    if (resultSet == nullptr) {
        return TELEPHONY_ERROR;
    }
    int32_t index;
    resultSet->GetColumnIndex(ContactData::DETAIL_INFO, index);
    resultSet->GetString(index, address_);
    resultSet->GetColumnIndex(ContactData::LABEL_NAME, index);
    resultSet->GetString(index, labelName_);
    resultSet->GetColumnIndex(ContactData::LABEL_ID, index);
    resultSet->GetString(index, labelId_);
    resultSet->GetColumnIndex(ContactData::ALIAS_DETAIL_INFO_KEY, index);
    resultSet->GetString(index, displayName_);
    return TELEPHONY_SUCCESS;
}

void VCardEmailData::InitEmailData(
    std::string &address, const std::string &labelId, std::string &labelName, std::string &displayName)
{
    address_ = address;
    labelId_ = labelId;
    labelName_ = labelName;
    displayName_ = displayName;
}

std::string VCardEmailData::GetAddress()
{
    return address_;
}

void VCardEmailData::SetAddress(const std::string &address)
{
    address_ = address;
}

std::string VCardEmailData::GetLabelId()
{
    return labelId_;
}

void VCardEmailData::SetLabelId(const std::string &labelId)
{
    labelId_ = labelId;
}

std::string VCardEmailData::GetLabelName()
{
    return labelName_;
}

void VCardEmailData::SetLabelName(const std::string &labelName)
{
    labelName_ = labelName;
}

std::string VCardEmailData::GetDisplayName()
{
    return displayName_;
}

void VCardEmailData::SetDisplayName(const std::string &displayName)
{
    displayName_ = displayName;
}

} // namespace Telephony
} // namespace OHOS
