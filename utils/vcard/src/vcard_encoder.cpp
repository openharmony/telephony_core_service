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
#include "vcard_encoder.h"

#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "vcard_constant.h"
#include "vcard_contact.h"

namespace OHOS {
namespace Telephony {
VCardEncoder::VCardEncoder(int32_t cardType, const std::string &charset)
{
    contructor_ = std::make_shared<VCardConstructor>(cardType, charset);
}

std::string VCardEncoder::ContructVCard(std::vector<std::vector<int>> contactIdLists, int32_t &errorCode)
{
    std::string result = "";
    for (int i = 0; i < (int32_t)contactIdLists.size(); i++) {
        std::vector<int> contactIdList = contactIdLists[i];
        TELEPHONY_LOGW("export progress %{public}d / %{public}d", i, (int32_t)contactIdLists.size());
        auto rawResultSet = GetRawContactResultSet(contactIdList);
        if (rawResultSet == nullptr) {
            TELEPHONY_LOGE("QueryRawContactId failed");
            errorCode = TELEPHONY_ERR_LOCAL_PTR_NULL;
            return "";
        }
        int rowCount = 0;
        rawResultSet->GetRowCount(rowCount);
        TELEPHONY_LOGI("rawResultSet rowCount = %{public}d", rowCount);
        if (rowCount == 0) {
            TELEPHONY_LOGW("rawResultSet is empty");
            continue;
        }
        std::vector<int32_t> rawContactIdList;
        int resultSetNum = rawResultSet->GoToFirstRow();
        while (resultSetNum == 0) {
            int32_t index = 0;
            int32_t rawContactId = 0;
            rawResultSet->GetColumnIndex(RawContact::ID, index);
            rawResultSet->GetInt(index, rawContactId);
            rawContactIdList.push_back(rawContactId);
            resultSetNum = rawResultSet->GoToNextRow();
        }
        rawResultSet->Close();
        TELEPHONY_LOGW("rawContactIdListSize = %{public}d", (int32_t)rawContactIdList.size());
        for (auto rawContactId : rawContactIdList) {
            std::shared_ptr<VCardContact> contact = std::make_shared<VCardContact>();
            ContructContact(contact, rawContactId, errorCode);
            result += contructor_->ContactVCard(contact);
        }
    }
    TELEPHONY_LOGW("ContructVCard Success");
    if (phoneNumberEncodedCallback_ != nullptr) {
        contructor_->SetPhoneNumberEncodedCallback(phoneNumberEncodedCallback_);
    }
    return result;
}

void VCardEncoder::SetPhoneNumberEncodedCallback(std::shared_ptr<PhoneNumberEncodedCallback> PhoneNumberEncodedCallback)
{
    phoneNumberEncodedCallback_ = PhoneNumberEncodedCallback;
}

void VCardEncoder::ContructContact(std::shared_ptr<VCardContact> contact,
    int32_t rawContactId, int32_t &errorCode)
{
    std::vector<std::string> columns;
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(ContactData::RAW_CONTACT_ID, rawContactId);
    auto contactDataResultSet = VCardRdbHelper::GetInstance().QueryContactData(columns, predicates);
    if (contactDataResultSet == nullptr) {
        TELEPHONY_LOGE("QueryContactData failed");
        errorCode = TELEPHONY_ERR_LOCAL_PTR_NULL;
        return;
    }
    int32_t contactDataResultSetNum = contactDataResultSet->GoToFirstRow();
    if (contactDataResultSetNum == 0) {
        contact->BuildContact(contactDataResultSet);
    }
    contactDataResultSet->Close();
}

std::shared_ptr<DataShare::DataShareResultSet> VCardEncoder::GetRawContactResultSet(std::vector<int> contactIdList)
{
    std::vector<std::string> columns;
    columns.push_back(RawContact::ID);
    DataShare::DataSharePredicates predicates;
    predicates.BeginWrap();
    for (size_t i = 0; i < contactIdList.size(); i++) {
        predicates.EqualTo(RawContact::CONTACT_ID, contactIdList[i]);
        if (i != contactIdList.size() - 1) {
            predicates.Or();
        }
    }
    predicates.EndWrap();
    predicates.And();
    predicates.EqualTo(RawContact::IS_DELETED, CONTACTS_NOT_DELETED);
    predicates.And();
    predicates.NotEqualTo(RawContact::PRIMARY_CONTACT, TELEPHONY_ERROR);
    return VCardRdbHelper::GetInstance().QueryRawContact(columns, predicates);
}

} // namespace Telephony
} // namespace OHOS