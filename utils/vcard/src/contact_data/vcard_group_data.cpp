/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "vcard_group_data.h"
#include "vcard_rdb_helper.h"
 
#include "telephony_errors.h"
 
namespace OHOS {
namespace Telephony {
 
int32_t VCardGroupData::BuildValuesBucket(OHOS::DataShare::DataShareValuesBucket &valuesBucket)
{
    valuesBucket.Put(ContactData::TYPE_ID, TypeId::GROUP);
    valuesBucket.Put(ContactData::DETAIL_INFO, groupId_);
    return TELEPHONY_SUCCESS;
}
 
int32_t VCardGroupData::BuildData(std::shared_ptr<DataShare::DataShareResultSet> resultSet)
{
    if (resultSet == nullptr) {
        return TELEPHONY_ERROR;
    }
    int32_t index;
    std::string groupId;
    resultSet->GetColumnIndex(ContactData::DETAIL_INFO, index);
    resultSet->GetString(index, groupId);
    groupId_ = std::stoi(groupId);
    std::vector<std::string> columns;
    OHOS::DataShare::DataSharePredicates predicates;
    predicates.EqualTo(Group::GROUP_ID, groupId_);
    predicates.EqualTo(Group::GROUP_IS_DELETED, 0);
    std::shared_ptr<DataShare::DataShareResultSet> nameResultSet =
        VCardRdbHelper::QueryGroupData(columns, predicates);
    if (nameResultSet == nullptr) {
        return DB_FAILD;
    }
    std::string groupName;
    if (nameResultSet->GoToFirstRow() == TELEPHONY_ERR_SUCCESS) {
        int curValueIndex;
        nameResultSet->GetColumnIndex(Group::GROUP_NAME, curValueIndex);
        nameResultSet->GetString(curValueIndex, groupName);
    }
    nameResultSet->Close();
    groupName_ = groupName;
    return TELEPHONY_SUCCESS;
}
 
void VCardGroupData::SetGroupName(std::string groupName)
{
    groupName_ = groupName;
}
 
std::string VCardGroupData::GetGroupName()
{
    return groupName_;
}
 
void VCardGroupData::SetGroupId(int32_t groupId)
{
    groupId_ = groupId;
}
 
int32_t VCardGroupData::GetGroupId()
{
    return groupId_;
}
 
} // namespace Telephony
} // namespace OHOS