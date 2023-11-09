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
#include "vcard_postal_data.h"

#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
namespace {
constexpr int32_t ADDR_MAX_DATA_SIZE = 7;
} // namespace

int32_t VCardPostalData::BuildValuesBucket(OHOS::DataShare::DataShareValuesBucket &valuesBucket)
{
    valuesBucket.Put(ContactData::TYPE_ID, TypeId::POSTAL_ADDRESS);
    std::string street = street_;
    if (street_.empty() && !neighborhood_.empty()) {
        street = neighborhood_;
    }
    if (!street_.empty() && !neighborhood_.empty()) {
        street = street + " " + neighborhood_;
    }
    valuesBucket.Put(ContactData::POBOX, pobox_);
    valuesBucket.Put(ContactData::POSTCODE, postCode_);
    valuesBucket.Put(ContactData::REGION, region_);
    valuesBucket.Put(ContactData::STREET, street_);
    valuesBucket.Put(ContactData::COUNTRY, country_);
    valuesBucket.Put(ContactData::CITY, city_);
    valuesBucket.Put(ContactData::LABEL_ID, labelId_);
    valuesBucket.Put(ContactData::LABEL_NAME, labelName_);
    valuesBucket.Put(ContactData::DETAIL_INFO, postalAddress_);
    return TELEPHONY_SUCCESS;
}

int32_t VCardPostalData::BuildData(std::shared_ptr<DataShare::DataShareResultSet> resultSet)
{
    if (resultSet == nullptr) {
        return TELEPHONY_ERROR;
    }
    int32_t index;
    resultSet->GetColumnIndex(ContactData::POBOX, index);
    resultSet->GetString(index, pobox_);
    resultSet->GetColumnIndex(ContactData::POSTCODE, index);
    resultSet->GetString(index, postCode_);
    resultSet->GetColumnIndex(ContactData::REGION, index);
    resultSet->GetString(index, region_);
    resultSet->GetColumnIndex(ContactData::STREET, index);
    resultSet->GetString(index, street_);
    resultSet->GetColumnIndex(ContactData::COUNTRY, index);
    resultSet->GetString(index, country_);
    resultSet->GetColumnIndex(ContactData::CITY, index);
    resultSet->GetString(index, city_);
    resultSet->GetColumnIndex(ContactData::LABEL_ID, index);
    resultSet->GetString(index, labelId_);
    resultSet->GetColumnIndex(ContactData::LABEL_NAME, index);
    resultSet->GetString(index, labelName_);
    resultSet->GetColumnIndex(ContactData::DETAIL_INFO, index);
    resultSet->GetString(index, postalAddress_);
    return TELEPHONY_SUCCESS;
}

void VCardPostalData::InitPostalData(std::vector<std::string> propValueList, int32_t type, std::string label)
{
    std::vector<std::string> dataArray(ADDR_MAX_DATA_SIZE, "");
    int32_t size = propValueList.size();
    if (size > ADDR_MAX_DATA_SIZE) {
        size = ADDR_MAX_DATA_SIZE;
    }
    int32_t i = 0;
    for (std::string addressElement : propValueList) {
        dataArray[i] = addressElement;
        if (++i >= size) {
            break;
        }
    }
    while (i < ADDR_MAX_DATA_SIZE) {
        dataArray[i++] = "";
    }
    pobox_ = dataArray[POBOX_VALUE_INDEX];
    postalAddress_ = dataArray[POSTAL_ADDRESS_VALUE_INDEX];
    street_ = dataArray[STREET_VALUE_INDEX];
    city_ = dataArray[CITY_VALUE_INDEX];
    region_ = dataArray[REGION_VALUE_INDEX];
    postCode_ = dataArray[POSTCODE_VALUE_INDEX];
    country_ = dataArray[COUNTRY_VALUE_INDEX];
    labelId_ = std::to_string(type);
    labelName_ = label;
}

std::string VCardPostalData::GetPOBox()
{
    return pobox_;
}

void VCardPostalData::SetPOBox(const std::string &pobox)
{
    pobox_ = pobox;
}

std::string VCardPostalData::GetPostCode()
{
    return postCode_;
}

void VCardPostalData::SetPostCode(const std::string &postCode)
{
    postCode_ = postCode;
}

std::string VCardPostalData::GetRegion()
{
    return region_;
}

void VCardPostalData::SetRegion(const std::string &region)
{
    region_ = region;
}

std::string VCardPostalData::GetCountry()
{
    return country_;
}

void VCardPostalData::SetCountry(const std::string &country)
{
    country_ = country;
}

std::string VCardPostalData::GetCity()
{
    return city_;
}

void VCardPostalData::SetCity(const std::string &city)
{
    city_ = city;
}

std::string VCardPostalData::GetStreet()
{
    return street_;
}

void VCardPostalData::SetStreet(const std::string &street)
{
    street_ = street;
}

std::string VCardPostalData::GetNeighborhood()
{
    return neighborhood_;
}

void VCardPostalData::SetNeighborhood(const std::string &neighborhood)
{
    neighborhood_ = neighborhood;
}

std::string VCardPostalData::GetPostalAddress()
{
    return postalAddress_;
}

void VCardPostalData::SetPostalAddress(const std::string &postalAddress)
{
    postalAddress_ = postalAddress;
}

std::string VCardPostalData::GetLabelId()
{
    return labelId_;
}

void VCardPostalData::SetLabelId(const std::string &labelId)
{
    labelId_ = labelId;
}

std::string VCardPostalData::GetLabelName()
{
    return labelName_;
}

void VCardPostalData::SetLabelName(const std::string &labelName)
{
    labelName_ = labelName;
}

} // namespace Telephony
} // namespace OHOS
