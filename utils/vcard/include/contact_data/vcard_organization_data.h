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

#ifndef OHOS_VCARD_ORGANIZATION_DATA_H
#define OHOS_VCARD_ORGANIZATION_DATA_H

#include "vcard_contact_data.h"

namespace OHOS {
namespace Telephony {
class VCardOrganizationData : public VCardContactData {
public:
    VCardOrganizationData()
    {
        organization_ = "";
        departmentName_ = "";
        title_ = "";
        phoneticName_ = "";
        type_ = 0;
        company_ = "";
    };
    ~VCardOrganizationData() {}
    virtual int32_t BuildValuesBucket(OHOS::DataShare::DataShareValuesBucket &valuesBucket);
    virtual int32_t BuildData(std::shared_ptr<DataShare::DataShareResultSet> resultSet);
    void InitOrganizationData(std::string &organization, std::string &departmentName, std::string &company,
        std::string &title, std::string &phoneticName, int32_t type);
    void SetOrganization(const std::string &organization);
    void SetDepartmentName(const std::string &departmentName);
    void SetTitle(const std::string &title);
    void SetPhoneticName(const std::string &phoneticName);
    void SetType(int32_t type);
    std::string GetOrganization();
    std::string GetDepartmentName();
    std::string GetTitle();
    std::string GetPhoneticName();
    int32_t GetType();
    void SetCompany(const std::string &company);
    std::string GetCompany();

private:
    std::string organization_;
    std::string departmentName_;
    std::string title_;
    std::string phoneticName_;
    int32_t type_;
    std::string company_;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_VCARD_ORGANIZATION_DATA_H
