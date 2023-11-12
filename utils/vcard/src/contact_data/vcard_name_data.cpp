/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License") {}
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
#include "vcard_name_data.h"

#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {

int32_t VCardNameData::BuildValuesBucket(OHOS::DataShare::DataShareValuesBucket &valuesBucket)
{
    valuesBucket.Put(ContactData::TYPE_ID, TypeId::NAME);
    if (!given_.empty()) {
        valuesBucket.Put(ContactData::GIVEN_NAME, given_);
    }
    if (!family_.empty()) {
        valuesBucket.Put(ContactData::FAMILY_NAME, family_);
    }
    if (!middle_.empty()) {
        valuesBucket.Put(ContactData::MIDDLE_NAME, middle_);
    }
    if (!prefix_.empty()) {
        valuesBucket.Put(ContactData::NAME_PREFIX, prefix_);
    }
    if (!suffix_.empty()) {
        valuesBucket.Put(ContactData::NAME_SUFFIX, suffix_);
    }
    bool isPhoneticNameSpecified = false;
    if (!phoneticGiven_.empty()) {
        valuesBucket.Put(ContactData::GIVEN_NAME_PHONETIC, phoneticGiven_);
        isPhoneticNameSpecified = true;
    }
    if (!phoneticFamily_.empty()) {
        valuesBucket.Put(ContactData::FAMILY_NAME_PHONETIC, phoneticFamily_);
        isPhoneticNameSpecified = true;
    }
    if (!phoneticMiddle_.empty()) {
        valuesBucket.Put(ContactData::MIDDLE_NAME_PHONETIC, phoneticMiddle_);
        isPhoneticNameSpecified = true;
    }
    if (!isPhoneticNameSpecified) {
        valuesBucket.Put(ContactData::GIVEN_NAME_PHONETIC, sort_);
    }
    valuesBucket.Put(ContactData::FULL_NAME, displayName_);
    return TELEPHONY_SUCCESS;
}

void VCardNameData::SetFamily(const std::string &family)
{
    family_ = family;
}

void VCardNameData::SetGiven(const std::string &given)
{
    given_ = given;
}

void VCardNameData::SetMiddle(const std::string &middle)
{
    middle_ = middle;
}

void VCardNameData::SetPrefix(const std::string &prefix)
{
    prefix_ = prefix;
}

void VCardNameData::SetSuffix(const std::string &suffix)
{
    suffix_ = suffix;
}

void VCardNameData::SetFormatted(const std::string &formatted)
{
    formatted_ = formatted;
}

void VCardNameData::SetPhoneticFamily(const std::string &phoneticFamily)
{
    phoneticFamily_ = phoneticFamily;
}

void VCardNameData::SetPhoneticGiven(const std::string &phoneticGiven)
{
    phoneticGiven_ = phoneticGiven;
}

void VCardNameData::SetPhoneticMiddle(const std::string &phoneticMiddle)
{
    phoneticMiddle_ = phoneticMiddle;
}

void VCardNameData::setSort(const std::string &sort)
{
    sort_ = sort;
}

void VCardNameData::setDispalyName(const std::string &displayName)
{
    displayName_ = displayName;
}

std::string VCardNameData::GetPrefix()
{
    return prefix_;
}

std::string VCardNameData::GetFamily()
{
    return family_;
}

std::string VCardNameData::GetGiven()
{
    return given_;
}

std::string VCardNameData::GetMiddle()
{
    return middle_;
}

std::string VCardNameData::GetSuffix()
{
    return suffix_;
}

std::string VCardNameData::GetFormatted()
{
    return formatted_;
}

std::string VCardNameData::GetPhoneticFamily()
{
    return phoneticFamily_;
}

std::string VCardNameData::GetPhoneticGiven()
{
    return phoneticGiven_;
}

std::string VCardNameData::GetPhoneticMiddle()
{
    return phoneticMiddle_;
}

std::string VCardNameData::GetSort()
{
    return sort_;
}

std::string VCardNameData::GetDisplayName()
{
    return displayName_;
}

int32_t VCardNameData::BuildData(std::shared_ptr<DataShare::DataShareResultSet> resultSet)
{
    if (resultSet == nullptr) {
        return TELEPHONY_ERROR;
    }
    int32_t index;
    resultSet->GetColumnIndex(ContactData::GIVEN_NAME, index);
    resultSet->GetString(index, given_);
    resultSet->GetColumnIndex(ContactData::FAMILY_NAME, index);
    resultSet->GetString(index, family_);
    resultSet->GetColumnIndex(ContactData::MIDDLE_NAME, index);
    resultSet->GetString(index, middle_);
    resultSet->GetColumnIndex(ContactData::NAME_PREFIX, index);
    resultSet->GetString(index, prefix_);
    resultSet->GetColumnIndex(ContactData::NAME_SUFFIX, index);
    resultSet->GetString(index, suffix_);
    resultSet->GetColumnIndex(ContactData::GIVEN_NAME_PHONETIC, index);
    resultSet->GetString(index, phoneticGiven_);
    resultSet->GetColumnIndex(ContactData::FAMILY_NAME_PHONETIC, index);
    resultSet->GetString(index, phoneticFamily_);
    resultSet->GetColumnIndex(ContactData::MIDDLE_NAME_PHONETIC, index);
    resultSet->GetString(index, phoneticMiddle_);
    resultSet->GetColumnIndex(ContactData::FULL_NAME, index);
    resultSet->GetString(index, displayName_);
    return TELEPHONY_SUCCESS;
}

} // namespace Telephony
} // namespace OHOS
