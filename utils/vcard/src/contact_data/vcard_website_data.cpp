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
#include "vcard_website_data.h"

#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {

int32_t VCardWebsiteData::BuildValuesBucket(OHOS::DataShare::DataShareValuesBucket &valuesBucket)
{
    valuesBucket.Put(ContactData::TYPE_ID, TypeId::WEBSITE);
    valuesBucket.Put(ContactData::DETAIL_INFO, website_);
    valuesBucket.Put(ContactData::LABEL_ID, labelId_);
    valuesBucket.Put(ContactData::LABEL_NAME, labelName_);
    return TELEPHONY_SUCCESS;
}

int32_t VCardWebsiteData::BuildData(std::shared_ptr<DataShare::DataShareResultSet> resultSet)
{
    if (resultSet == nullptr) {
        return TELEPHONY_ERROR;
    }
    int32_t index;
    resultSet->GetColumnIndex(ContactData::DETAIL_INFO, index);
    resultSet->GetString(index, website_);
    resultSet->GetColumnIndex(ContactData::LABEL_NAME, index);
    resultSet->GetString(index, labelName_);
    resultSet->GetColumnIndex(ContactData::LABEL_ID, index);
    resultSet->GetString(index, labelId_);
    return TELEPHONY_SUCCESS;
}

void VCardWebsiteData::InitWebsite(std::string website)
{
    website_ = website;
}

void VCardWebsiteData::SetWebsite(const std::string &website)
{
    website_ = website;
}

std::string VCardWebsiteData::GetWebsite()
{
    return website_;
}

void VCardWebsiteData::SetLabelId(const std::string &labelId)
{
    labelId_ = labelId;
}

std::string VCardWebsiteData::GetLabelId()
{
    return labelId_;
}

void VCardWebsiteData::SetLabelName(const std::string &labelName)
{
    labelName_ = labelName;
}

std::string VCardWebsiteData::GetLabelName()
{
    return labelName_;
}

} // namespace Telephony
} // namespace OHOS