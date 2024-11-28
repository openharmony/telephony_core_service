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

std::string VCardEncoder::ContructVCard(std::shared_ptr<DataShare::DataShareResultSet> resultSet, int32_t &errorCode)
{
    if (resultSet == nullptr) {
        TELEPHONY_LOGE("resultSet is null");
        return "";
    }
    int32_t index = 0;
    int32_t id = 0;
    resultSet->GetColumnIndex(Contact::ID, index);
    resultSet->GetInt(index, id);
    std::vector<std::string> columns;
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(RawContact::CONTACT_ID, id)->And()->EqualTo(RawContact::IS_DELETED, CONTACTS_NOT_DELETED);
    predicates.NotEqualTo(RawContact::PRIMARY_CONTACT, TELEPHONY_ERROR);
    auto rawResultSet = VCardRdbHelper::GetInstance().QueryRawContact(columns, predicates);
    if (rawResultSet == nullptr) {
        TELEPHONY_LOGE("QueryContactData failed");
        errorCode = TELEPHONY_ERR_LOCAL_PTR_NULL;
        return "";
    }
    int rowCount = 0;
    rawResultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        return "";
    }
    std::shared_ptr<VCardContact> contact = std::make_shared<VCardContact>();
    ContructContact(contact, rawResultSet, errorCode);
    rawResultSet->Close();
    if (phoneNumberEncodedCallback_ != nullptr) {
        contructor_->SetPhoneNumberEncodedCallback(phoneNumberEncodedCallback_);
    }
    return contructor_->ContactVCard(contact);
}

void VCardEncoder::SetPhoneNumberEncodedCallback(std::shared_ptr<PhoneNumberEncodedCallback> PhoneNumberEncodedCallback)
{
    phoneNumberEncodedCallback_ = PhoneNumberEncodedCallback;
}

void VCardEncoder::ContructContact(std::shared_ptr<VCardContact> contact,
    std::shared_ptr<DataShare::DataShareResultSet> rawResultSet, int32_t &errorCode)
{
    if (rawResultSet == nullptr) {
        TELEPHONY_LOGE("rawResultSet is nullptr!");
        return;
    }
    int32_t rawResultSetNum = rawResultSet->GoToFirstRow();
    while (rawResultSetNum == 0 && errorCode == TELEPHONY_SUCCESS) {
        int32_t index = 0;
        int32_t rawContactId;
        rawResultSet->GetColumnIndex(RawContact::CONTACT_ID, index);
        rawResultSet->GetInt(index, rawContactId);
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
        rawResultSetNum = rawResultSet->GoToNextRow();
    }
}
} // namespace Telephony
} // namespace OHOS
