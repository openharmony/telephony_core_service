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

#ifndef OHOS_VCARD_CONSTRUCTOR_H
#define OHOS_VCARD_CONSTRUCTOR_H

#include <memory>
#include <sstream>

#include "vcard_configuration.h"
#include "vcard_contact.h"

namespace OHOS {
namespace Telephony {
class PhoneNumberEncodedCallback {
public:
    virtual void onCallback(std::string number, int type, std::string label, bool primary) = 0;
};

class VCardConstructor {
public:
    explicit VCardConstructor(int32_t cardType = VCardConfiguration::VER_21, const std::string &charset = "UTF-8");
    std::string ContactVCard(std::shared_ptr<VCardContact> contact);
    void SetPhoneNumberEncodedCallback(std::shared_ptr<PhoneNumberEncodedCallback> phoneNumberEncodedCallback);
    void ContactBegin();
    void ContactEnd();
    void AddNameData(const std::string &family, const std::string &given, const std::string &middle,
        const std::string &prefix, const std::string &suffix);
    int32_t ConstructPhoneticNameFields(std::shared_ptr<VCardNameData> nameData);
    int32_t AddPhoneticName(const std::string &phoneticType, const std::string &phoneticName);
    void DealNoEmptyFimilyOrGivenName(const std::string &familyName, const std::string &givenName,
        const std::string &middleName, const std::string &prefix, const std::string &suffix,
        const std::string &displayName);
    void AddCharsetOrQuotedPrintable(bool needAddCharset, bool needAddQuotedPrintable);
    void AddSinglePartNameField(std::string property, std::string part);
    void AddCustomType(const std::string &type, std::vector<std::string> values);
    void HandleCharacter(int32_t i, int32_t length, std::string value, std::string &temp);
    std::string DealCharacters(std::string value);
    std::string EncodeQuotedPrintable(const std::string &input);
    bool IsNeedCharsetParam(std::vector<std::string> strs);
    void AddLine(const std::string &type, const std::string &rawValue);
    void AddLine(const std::string &type, std::vector<std::string> valueList);
    void AddLine(const std::string &type, const std::string &rawValue, bool needCharset, bool needQuotedPrintable);
    void AddLine(const std::string &type, const std::vector<std::string> &paramList, const std::string &rawValue);
    void AddLine(const std::string &type, const std::vector<std::string> &paramList, const std::string &rawValue,
        bool needCharset, bool useQuotedPrintable);
    void AddLine(
        const std::string &type, std::vector<std::string> valueList, bool needCharset, bool needQuotedPrintable);
    void AddLine(const std::string &type, const std::vector<std::string> &paramList, std::vector<std::string> valueList,
        bool needCharset, bool needQuotedPrintable);
    void AddParamType(const std::string &paramType);
    void AddParamTypes(std::vector<std::string> types);
    void AddParamType(std::stringstream &result, const std::string &paramType);
    std::string FormatFullName(
        const std::string &givenName, const std::string &middleName, const std::string &familyName);
    void AddLineWithCharsetAndQP(const std::string &type, std::vector<std::string> valueList);
    void AddTelLine(const std::string &labelId, const std::string &labelName, const std::string &number);
    void AddPhotoLine(const std::string &encodedValue, const std::string &photoType);
    void AddEmailLine(
        int32_t emailType, const std::string &labelName, const std::string &email, const std::string &displayName);
    void ConstructPostalLine(std::shared_ptr<VCardPostalData> postalData, std::stringstream &postalLine,
        bool &needCharset, bool &needAddQuotedPrintable);
    void AddPostalLine(std::shared_ptr<VCardPostalData> postalData, int32_t postalType, const std::string &labelName);
    std::string ToString();

private:
    int32_t ConstructName(std::shared_ptr<VCardContact> contact);
    int32_t ConstructPhones(std::shared_ptr<VCardContact> contact);
    int32_t ConstructRelation(std::shared_ptr<VCardContact> contact);
    int32_t ConstructIms(std::shared_ptr<VCardContact> contact);
    int32_t ConstructSipAddresses(std::shared_ptr<VCardContact> contact);
    int32_t ConstructNickNames(std::shared_ptr<VCardContact> contact);
    int32_t ConstructEmails(std::shared_ptr<VCardContact> contact);
    int32_t ConstructPostals(std::shared_ptr<VCardContact> contact);
    int32_t ConstructOrganizations(std::shared_ptr<VCardContact> contact);
    int32_t ConstructWebsites(std::shared_ptr<VCardContact> contact);
    int32_t ConstructPhotos(std::shared_ptr<VCardContact> contact);
    int32_t ConstructNotes(std::shared_ptr<VCardContact> contact);
    int32_t ConstructEvents(std::shared_ptr<VCardContact> contact);
    int32_t ConstructNameV40(std::shared_ptr<VCardContact> contact);

private:
    size_t headLength_;
    int32_t cardType_;
    std::string charset_;
    std::stringstream result_;
    std::string charsetParam_;
    std::shared_ptr<PhoneNumberEncodedCallback> phoneNumberEncodedCallback_;
    bool isV30OrV40_;
    bool needCharsetParam_;
    bool needQP_;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_VCARD_CONSTRUCTOR_H
