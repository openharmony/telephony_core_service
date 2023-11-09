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
#include "vcard_im_data.h"

#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {

int32_t VCardImData::BuildValuesBucket(OHOS::DataShare::DataShareValuesBucket &valuesBucket)
{
    valuesBucket.Put(ContactData::TYPE_ID, TypeId::IM);
    valuesBucket.Put(ContactData::DETAIL_INFO, address_);
    valuesBucket.Put(ContactData::LABEL_ID, labelId_);
    return TELEPHONY_SUCCESS;
}

int32_t VCardImData::BuildData(std::shared_ptr<DataShare::DataShareResultSet> resultSet)
{
    if (resultSet == nullptr) {
        return TELEPHONY_ERROR;
    }
    int32_t index;
    resultSet->GetColumnIndex(ContactData::DETAIL_INFO, index);
    resultSet->GetString(index, address_);
    resultSet->GetColumnIndex(ContactData::LABEL_ID, index);
    resultSet->GetString(index, labelId_);
    return TELEPHONY_SUCCESS;
}

void VCardImData::SetAddress(const std::string &address)
{
    address_ = address;
}

std::string VCardImData::GetAddress()
{
    return address_;
}

void VCardImData::SetLabelId(const std::string &labelId)
{
    labelId_ = labelId;
}

std::string VCardImData::GetLabelId()
{
    return labelId_;
}

} // namespace Telephony
} // namespace OHOS
