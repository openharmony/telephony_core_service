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
#include "vcard_rdb_helper.h"

#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {

namespace {
OHOS::Uri uriRawContact("datashare:///com.ohos.contactsdataability/contacts/raw_contact");
OHOS::Uri uriContactData("datashare:///com.ohos.contactsdataability/contacts/contact_data");
OHOS::Uri uriAccount("datashare:///com.ohos.contactsdataability/contacts/account");
OHOS::Uri uriContact("datashare:///com.ohos.contactsdataability/contacts/contact");
OHOS::Uri uriRawContactMaxId("datashare:///com.ohos.contactsdataability/raw_contact/get_inc_id");
OHOS::Uri uriGroup("datashare:///com.ohos.contactsdataability/contacts/groups");

} // namespace

std::shared_ptr<DataShare::DataShareHelper> VCardRdbHelper::dataShareHelper_ = nullptr;

VCardRdbHelper::VCardRdbHelper() {}

VCardRdbHelper &VCardRdbHelper::GetInstance()
{
    static VCardRdbHelper instance;
    return instance;
}

int32_t VCardRdbHelper::QueryRawContactMaxId()
{
    if (dataShareHelper_ == nullptr) {
        TELEPHONY_LOGE("dataShareHelper is nullptr");
        return DB_FAILD;
    }
    Uri uriRawContactMaxIdQuery(uriRawContactMaxId.ToString() + "?isFromBatch=true");
    std::vector<std::string> columns;
    DataShare::DataSharePredicates predicates;
    std::shared_ptr<DataShare::DataShareResultSet> resultSet =
        dataShareHelper_->Query(uriRawContactMaxIdQuery, predicates, columns);
    if (resultSet == nullptr) {
        TELEPHONY_LOGE("resultSet is nullptr");
        return DB_FAILD;
    }
    int rawMaxId = 0;
    if (resultSet->GoToFirstRow() == TELEPHONY_ERR_SUCCESS) {
        int curValueIndex;
        resultSet->GetColumnIndex("seq", curValueIndex);
        resultSet->GetInt(curValueIndex, rawMaxId);
    }
    TELEPHONY_LOGI("batchInsert rawId: %{public}d", rawMaxId);
    return rawMaxId;
}

int32_t VCardRdbHelper::BatchInsertRawContact(const std::vector<DataShare::DataShareValuesBucket> &rawContactValues)
{
    if (dataShareHelper_ == nullptr) {
        TELEPHONY_LOGE("dataShareHelper_ is nullptr");
        return DB_FAILD;
    }
    Uri uriRawContactBatch(uriRawContact.ToString() + "?isFromBatch=true");
    int code = dataShareHelper_->BatchInsert(uriRawContactBatch, rawContactValues);
    TELEPHONY_LOGI("insert code %{public}d", code);
    return code;
}

int32_t VCardRdbHelper::BatchInsertContactData(const std::vector<DataShare::DataShareValuesBucket> &contactsDataValues)
{
    if (dataShareHelper_ == nullptr) {
        TELEPHONY_LOGE("dataShareHelper_ is nullptr");
        return DB_FAILD;
    }
    Uri uriContactDataBatch(uriContactData.ToString() + "?isFromBatch=true&isSyncFromCloud=true");
    int code = dataShareHelper_->BatchInsert(uriContactDataBatch, contactsDataValues);
    TELEPHONY_LOGI("insert code %{public}d", code);
    return code;
}

int32_t VCardRdbHelper::InsertRawContact(const DataShare::DataShareValuesBucket &rawContactValues)
{
    if (dataShareHelper_ == nullptr) {
        TELEPHONY_LOGE("dataShareHelper_ is nullptr");
        return DB_FAILD;
    }
    int rawContactId = dataShareHelper_->Insert(uriRawContact, rawContactValues);
    TELEPHONY_LOGI("RawContactInsert insert rawContactId %{public}d", rawContactId);
    return rawContactId;
}

int32_t VCardRdbHelper::InsertContactData(const std::vector<DataShare::DataShareValuesBucket> &contactsDataValues)
{
    if (dataShareHelper_ == nullptr) {
        TELEPHONY_LOGE("dataShareHelper_ is nullptr");
        return DB_FAILD;
    }
    int code = dataShareHelper_->BatchInsert(uriContactData, contactsDataValues);
    TELEPHONY_LOGI(" ContactsControl::ContactDataInsert insert code %{public}d", code);
    return code;
}

int32_t VCardRdbHelper::InsertGroupData(const DataShare::DataShareValuesBucket &groupDataValue)
{
    if (dataShareHelper_ == nullptr) {
        TELEPHONY_LOGE("dataShareHelper_ is nullptr");
        return DB_FAILD;
    }
    int groupId = dataShareHelper_->Insert(uriGroup, groupDataValue);
    TELEPHONY_LOGI("InsertGroupData insert groupId %{public}d", groupId);
    return groupId;
}
 
std::shared_ptr<DataShare::DataShareResultSet> VCardRdbHelper::QueryGroupData(
    std::vector<std::string> &columns, const DataShare::DataSharePredicates &predicates)
{
    if (dataShareHelper_ == nullptr) {
        TELEPHONY_LOGE("dataShareHelper_ is nullptr");
        return nullptr;
    }
    std::shared_ptr<DataShare::DataShareResultSet> resultSet =
        dataShareHelper_->Query(uriGroup, predicates, columns);
    return resultSet;
}
 
int32_t VCardRdbHelper::QueryGroupId(std::string groupName)
{
    std::vector<std::string> columns;
    OHOS::DataShare::DataSharePredicates predicates;
    predicates.EqualTo(Group::GROUP_NAME, groupName);
    predicates.EqualTo(Group::GROUP_IS_DELETED, 0);
    std::shared_ptr<DataShare::DataShareResultSet> resultSet = QueryGroupData(columns, predicates);
    if (resultSet == nullptr) {
        TELEPHONY_LOGE("resultSet is nullptr");
        return DB_FAILD;
    }
    int32_t groupId;
    if (resultSet->GoToFirstRow() == TELEPHONY_ERR_SUCCESS) {
        int curValueIndex;
        resultSet->GetColumnIndex(Group::GROUP_ID, curValueIndex);
        resultSet->GetInt(curValueIndex, groupId);
        resultSet->Close();
        return groupId;
    }
    resultSet->Close();
    OHOS::DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(Group::GROUP_NAME, groupName);
    valuesBucket.Put(Group::GROUP_ACCOUNT_ID, 1);
    return VCardRdbHelper::InsertGroupData(valuesBucket);
}

std::shared_ptr<DataShare::DataShareResultSet> VCardRdbHelper::QueryAccount(
    std::vector<std::string> &columns, const DataShare::DataSharePredicates &predicates)
{
    if (dataShareHelper_ == nullptr) {
        TELEPHONY_LOGE("dataShareHelper_ is nullptr");
        return nullptr;
    }
    std::shared_ptr<DataShare::DataShareResultSet> resultSet = dataShareHelper_->Query(uriAccount, predicates, columns);
    return resultSet;
}

std::shared_ptr<DataShare::DataShareResultSet> VCardRdbHelper::QueryContact(
    std::vector<std::string> &columns, const DataShare::DataSharePredicates &predicates)
{
    if (dataShareHelper_ == nullptr) {
        TELEPHONY_LOGE("dataShareHelper_ is nullptr");
        return nullptr;
    }
    std::shared_ptr<DataShare::DataShareResultSet> resultSet = dataShareHelper_->Query(uriContact, predicates, columns);
    return resultSet;
}

std::shared_ptr<DataShare::DataShareResultSet> VCardRdbHelper::QueryRawContact(
    std::vector<std::string> &columns, const DataShare::DataSharePredicates &predicates)
{
    if (dataShareHelper_ == nullptr) {
        TELEPHONY_LOGE("dataShareHelper_ is nullptr");
        return nullptr;
    }
    std::shared_ptr<DataShare::DataShareResultSet> resultSet =
        dataShareHelper_->Query(uriRawContact, predicates, columns);
    return resultSet;
}

std::shared_ptr<DataShare::DataShareResultSet> VCardRdbHelper::QueryContactData(
    std::vector<std::string> &columns, const DataShare::DataSharePredicates &predicates)
{
    if (dataShareHelper_ == nullptr) {
        TELEPHONY_LOGE("dataShareHelper_ is nullptr");
        return nullptr;
    }
    std::shared_ptr<DataShare::DataShareResultSet> resultSet =
        dataShareHelper_->Query(uriContactData, predicates, columns);
    return resultSet;
}

void VCardRdbHelper::SetDataHelper(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper)
{
    dataShareHelper_ = dataShareHelper;
}

void VCardRdbHelper::Release()
{
    if (dataShareHelper_ != nullptr) {
        dataShareHelper_->Release();
        dataShareHelper_ = nullptr;
    }
}

} // namespace Telephony
} // namespace OHOS
