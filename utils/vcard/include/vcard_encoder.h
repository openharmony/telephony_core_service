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

#ifndef OHOS_VCARD_ENCODER_H
#define OHOS_VCARD_ENCODER_H

#include <memory>

#include "vcard_constructor.h"

namespace OHOS {
namespace Telephony {
class VCardEncoder {
public:
    explicit VCardEncoder(int32_t cardType = VCardConfiguration::VER_21, const std::string &charset = "UTF-8");
    std::string ContructVCard(std::vector<std::vector<int>> contactIdList, int32_t &errorCode);
    void SetPhoneNumberEncodedCallback(std::shared_ptr<PhoneNumberEncodedCallback> PhoneNumberEncodedCallback);

private:
    std::shared_ptr<DataShare::DataShareResultSet> QueryContactData(
        const std::vector<int32_t> &rawContactIdList, int32_t &errorCode);
    void ProcessContactData(std::string &result,
        std::shared_ptr<DataShare::DataShareResultSet> contactDataResultSet, int32_t &errorCode);
    std::shared_ptr<DataShare::DataShareResultSet> GetRawContactResultSet(std::vector<int> contactIdList);

private:
    std::shared_ptr<PhoneNumberEncodedCallback> phoneNumberEncodedCallback_ = nullptr;
    std::shared_ptr<VCardConstructor> contructor_ = nullptr;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_VCARD_ENCODER_H