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
#include "vcard_relation_data.h"

#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {

int32_t VCardRelationData::BuildValuesBucket(OHOS::DataShare::DataShareValuesBucket &valuesBucket)
{
    valuesBucket.Put(ContactData::TYPE_ID, TypeId::RELATION);
    valuesBucket.Put(ContactData::LABEL_ID, labelId_);
    valuesBucket.Put(ContactData::LABEL_NAME, labelName_);
    valuesBucket.Put(ContactData::DETAIL_INFO, relationName_);
    return TELEPHONY_SUCCESS;
}

int32_t VCardRelationData::BuildData(std::shared_ptr<DataShare::DataShareResultSet> resultSet)
{
    if (resultSet == nullptr) {
        return TELEPHONY_ERROR;
    }
    int32_t index;
    resultSet->GetColumnIndex(ContactData::DETAIL_INFO, index);
    resultSet->GetString(index, relationName_);
    resultSet->GetColumnIndex(ContactData::LABEL_NAME, index);
    resultSet->GetString(index, labelName_);
    resultSet->GetColumnIndex(ContactData::LABEL_ID, index);
    resultSet->GetString(index, labelId_);
    return TELEPHONY_SUCCESS;
}

void VCardRelationData::SetRelationName(const std::string &name)
{
    relationName_ = name;
}

std::string VCardRelationData::GetRelationName()
{
    return relationName_;
}

void VCardRelationData::SetLabelId(const std::string &id)
{
    labelId_ = id;
}

std::string VCardRelationData::GetLabelId()
{
    return labelId_;
}

void VCardRelationData::SetLabelName(const std::string &name)
{
    labelName_ = name;
}

std::string VCardRelationData::GetLabelName()
{
    return labelName_;
}

} // namespace Telephony
} // namespace OHOS
