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

#ifndef OHOS_VCARD_NAME_DATA_H
#define OHOS_VCARD_NAME_DATA_H

#include "vcard_contact_data.h"

namespace OHOS {
namespace Telephony {
class VCardNameData : public VCardContactData {
public:
    VCardNameData()
    {
        family_ = "";
        given_ = "";
        middle_ = "";
        prefix_ = "";
        suffix_ = "";
        formatted_ = "";
        phoneticFamily_ = "";
        phoneticGiven_ = "";
        phoneticMiddle_ = "";
        sort_ = "";
        displayName_ = "";
    };
    ~VCardNameData() {}
    virtual int32_t BuildValuesBucket(OHOS::DataShare::DataShareValuesBucket &valuesBucket);
    virtual int32_t BuildData(std::shared_ptr<DataShare::DataShareResultSet> resultSet);
    void SetFamily(const std::string &family);
    void SetGiven(const std::string &given);
    void SetMiddle(const std::string &middle);
    void SetPrefix(const std::string &prefix);
    void SetSuffix(const std::string &suffix);
    void SetFormatted(const std::string &famformatted);
    void SetPhoneticFamily(const std::string &phoneticFamily);
    void SetPhoneticGiven(const std::string &phoneticGiven);
    void SetPhoneticMiddle(const std::string &phoneticMiddle);
    void setSort(const std::string &sort);
    void setDispalyName(const std::string &displayName);
    std::string GetFamily();
    std::string GetGiven();
    std::string GetMiddle();
    std::string GetPrefix();
    std::string GetSuffix();
    std::string GetFormatted();
    std::string GetPhoneticFamily();
    std::string GetPhoneticGiven();
    std::string GetPhoneticMiddle();
    std::string GetSort();
    std::string GetDisplayName();

private:
    std::string family_;
    std::string given_;
    std::string middle_;
    std::string prefix_;
    std::string suffix_;
    std::string formatted_;
    std::string phoneticFamily_;
    std::string phoneticGiven_;
    std::string phoneticMiddle_;
    std::string sort_;
    std::string displayName_;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_VCARD_NAME_DATA_H