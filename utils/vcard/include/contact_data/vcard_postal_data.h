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

#ifndef OHOS_VCARD_POSTAL_DATA_H
#define OHOS_VCARD_POSTAL_DATA_H

#include "vcard_contact_data.h"

namespace OHOS {
namespace Telephony {
class VCardPostalData : public VCardContactData {
public:
    VCardPostalData()
    {
        pobox_ = "";
        extendedAddress_ = "";
        street_ = "";
        region_ = "";
        postCode_ = "";
        country_ = "";
        city_ = "";
        type_ = 0;
        postalAddress_ = "";
        localty_ = "";
        postalCode_ = "";
        label_ = "";
        neighborhood_ = "";
        labelId_ = "";
        labelName_ = "";
    };
    ~VCardPostalData() {}
    virtual int32_t BuildValuesBucket(OHOS::DataShare::DataShareValuesBucket &valuesBucket);
    virtual int32_t BuildData(std::shared_ptr<DataShare::DataShareResultSet> resultSet);
    void InitPostalData(std::vector<std::string> propValueList, int32_t type, std::string label);
    std::string GetPOBox();
    void SetPOBox(const std::string &pobox);
    std::string GetPostCode();
    void SetPostCode(const std::string &postCode);
    std::string GetRegion();
    void SetRegion(const std::string &region);
    std::string GetCountry();
    void SetCountry(const std::string &country);
    std::string GetCity();
    void SetCity(const std::string &city);
    std::string GetStreet();
    void SetStreet(const std::string &street);
    std::string GetNeighborhood();
    void SetNeighborhood(const std::string &neighborhood);
    std::string GetPostalAddress();
    void SetPostalAddress(const std::string &postalAddress);
    std::string GetLabelId();
    void SetLabelId(const std::string &labelId);
    std::string GetLabelName();
    void SetLabelName(const std::string &labelName);

private:
    const int32_t POBOX_VALUE_INDEX = 0;
    const int32_t POSTAL_ADDRESS_VALUE_INDEX = 1;
    const int32_t STREET_VALUE_INDEX = 2;
    const int32_t CITY_VALUE_INDEX = 3;
    const int32_t REGION_VALUE_INDEX = 4;
    const int32_t POSTCODE_VALUE_INDEX = 5;
    const int32_t COUNTRY_VALUE_INDEX = 6;
    std::string pobox_;
    std::string extendedAddress_;
    std::string street_;
    std::string localty_;
    std::string region_;
    std::string postalCode_;
    std::string country_;
    std::string city_;
    int32_t type_;
    std::string label_;
    std::string postCode_;
    std::string neighborhood_;
    std::string postalAddress_;
    std::string labelId_;
    std::string labelName_;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_VCARD_POSTAL_DATA_H
