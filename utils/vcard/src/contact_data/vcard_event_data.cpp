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
#include "vcard_event_data.h"

#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {

int32_t VCardEventData::BuildValuesBucket(OHOS::DataShare::DataShareValuesBucket &valuesBucket)
{
    valuesBucket.Put(ContactData::TYPE_ID, TypeId::CONTACT_EVENT);
    valuesBucket.Put(ContactData::LABEL_ID, labelId_);
    valuesBucket.Put(ContactData::LABEL_NAME, labelName_);
    valuesBucket.Put(ContactData::DETAIL_INFO, eventDate_);
    return TELEPHONY_SUCCESS;
}

int32_t VCardEventData::BuildData(std::shared_ptr<DataShare::DataShareResultSet> resultSet)
{
    if (resultSet == nullptr) {
        return TELEPHONY_ERROR;
    }
    int32_t index;
    resultSet->GetColumnIndex(ContactData::DETAIL_INFO, index);
    resultSet->GetString(index, eventDate_);
    resultSet->GetColumnIndex(ContactData::LABEL_NAME, index);
    resultSet->GetString(index, labelName_);
    resultSet->GetColumnIndex(ContactData::LABEL_ID, index);
    resultSet->GetString(index, labelId_);
    return TELEPHONY_SUCCESS;
}

std::string VCardEventData::GetEventDate()
{
    return eventDate_;
}

void VCardEventData::SetEventDate(const std::string &eventDate)
{
    eventDate_ = eventDate;
}

std::string VCardEventData::GetLabelId()
{
    return labelId_;
}

void VCardEventData::SetLabelId(const std::string &labelId)
{
    labelId_ = labelId;
}

std::string VCardEventData::GetLabelName()
{
    return labelName_;
}

void VCardEventData::SetLabelName(const std::string &labelName)
{
    labelName_ = labelName;
}

} // namespace Telephony
} // namespace OHOS
