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
#include "vcard_organization_data.h"

#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {

int32_t VCardOrganizationData::BuildValuesBucket(OHOS::DataShare::DataShareValuesBucket &valuesBucket)
{
    valuesBucket.Put(ContactData::TYPE_ID, TypeId::ORGANIZATION);
    if (!company_.empty()) {
        valuesBucket.Put(ContactData::DETAIL_INFO, company_);
    }
    if (!title_.empty()) {
        valuesBucket.Put(ContactData::POSITION, title_);
    }
    return TELEPHONY_SUCCESS;
}

int32_t VCardOrganizationData::BuildData(std::shared_ptr<DataShare::DataShareResultSet> resultSet)
{
    if (resultSet == nullptr) {
        return TELEPHONY_ERROR;
    }
    int32_t index;
    resultSet->GetColumnIndex(ContactData::DETAIL_INFO, index);
    resultSet->GetString(index, company_);
    resultSet->GetColumnIndex(ContactData::POSITION, index);
    resultSet->GetString(index, title_);
    return TELEPHONY_SUCCESS;
}

void VCardOrganizationData::InitOrganizationData(std::string &organization, std::string &departmentName,
    std::string &company, std::string &title, std::string &phoneticName, int32_t type)
{
    type_ = type;
    organization_ = organization;
    departmentName_ = departmentName;
    phoneticName_ = phoneticName;
    company_ = company;
    title_ = title;
}

void VCardOrganizationData::SetOrganization(const std::string &organization)
{
    organization_ = organization;
}

void VCardOrganizationData::SetDepartmentName(const std::string &departmentName)
{
    departmentName_ = departmentName;
}

void VCardOrganizationData::SetTitle(const std::string &title)
{
    title_ = title;
}

void VCardOrganizationData::SetPhoneticName(const std::string &phoneticName)
{
    phoneticName_ = phoneticName;
}

void VCardOrganizationData::SetType(int32_t type)
{
    type_ = type;
}

std::string VCardOrganizationData::GetOrganization()
{
    return organization_;
}

std::string VCardOrganizationData::GetDepartmentName()
{
    return departmentName_;
}

std::string VCardOrganizationData::GetTitle()
{
    return title_;
}

std::string VCardOrganizationData::GetPhoneticName()
{
    return phoneticName_;
}

int32_t VCardOrganizationData::GetType()
{
    return type_;
}

void VCardOrganizationData::SetCompany(const std::string &company)
{
    company_ = company;
}

std::string VCardOrganizationData::GetCompany()
{
    return company_;
}

} // namespace Telephony
} // namespace OHOS
