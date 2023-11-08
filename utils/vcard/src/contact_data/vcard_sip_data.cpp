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
#include "vcard_sip_data.h"

#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "vcard_utils.h"

namespace OHOS {
namespace Telephony {

int32_t VCardSipData::BuildValuesBucket(OHOS::DataShare::DataShareValuesBucket &valuesBucket)
{
    valuesBucket.Put(ContactData::TYPE_ID, TypeId::SIP_ADDRESS);
    valuesBucket.Put(ContactData::DETAIL_INFO, address_);
    valuesBucket.Put(ContactData::LABEL_ID, labelId_);
    valuesBucket.Put(ContactData::LABEL_NAME, labelName_);
    return TELEPHONY_SUCCESS;
}

int32_t VCardSipData::BuildData(std::shared_ptr<DataShare::DataShareResultSet> resultSet)
{
    if (resultSet == nullptr) {
        return TELEPHONY_ERROR;
    }
    int32_t index;
    resultSet->GetColumnIndex(ContactData::DETAIL_INFO, index);
    resultSet->GetString(index, address_);
    resultSet->GetColumnIndex(ContactData::LABEL_NAME, index);
    resultSet->GetString(index, labelName_);
    resultSet->GetColumnIndex(ContactData::LABEL_ID, index);
    resultSet->GetString(index, labelId_);
    return TELEPHONY_SUCCESS;
}

void VCardSipData::InitSipData(std::string rawSip, int32_t type, std::string label)
{
    if (VCardUtils::StartWith(rawSip, "sip:")) {
        address_ = rawSip.substr(SIP_ADDRESS_VALUE_INDEX);
    } else {
        address_ = rawSip;
    }
    type_ = type;
    labelName_ = label;
}

void VCardSipData::SetAddress(const std::string &address)
{
    address_ = address;
}

std::string VCardSipData::GetAddress()
{
    return address_;
}

void VCardSipData::SetLabelId(const std::string &labelId)
{
    labelId_ = labelId;
}

std::string VCardSipData::GetLabelId()
{
    return labelId_;
}

void VCardSipData::SetLabelName(const std::string &labelName)
{
    labelName_ = labelName;
}

std::string VCardSipData::GetLabelName()
{
    return labelName_;
}

void VCardSipData::SetType(int32_t type)
{
    type_ = type;
}

int32_t VCardSipData::GetType()
{
    return type_;
}

} // namespace Telephony
} // namespace OHOS
