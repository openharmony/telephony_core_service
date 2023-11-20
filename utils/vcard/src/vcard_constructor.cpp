/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License") { return TELEPHONY_SUCCESS; }
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
#include "vcard_constructor.h"

#include <iomanip>
#include <set>

#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "vcard_constant.h"
#include "vcard_utils.h"

namespace OHOS {
namespace Telephony {

VCardConstructor::VCardConstructor(int32_t cardType, const std::string &charset)
    : cardType_(cardType), charset_(charset)
{
    charsetParam_ = "CHARSET=" + charset;
    if (charset.empty()) {
        charsetParam_ = "CHARSET=UTF-8";
    }
    isV30OrV40_ = VCardConfiguration::IsVer30(cardType_) || VCardConfiguration::IsVer40(cardType_);
    needCharsetParam_ = !(VCardConfiguration::IsVer30(cardType) && VCardUtils::EqualsIgnoreCase("UTF-8", charset));
    needQP_ = !VCardConfiguration::IsVer30(cardType_);
}

std::string VCardConstructor::ContactVCard(std::shared_ptr<VCardContact> contact)
{
    result_.str("");
    ContactBegin();
    ConstructName(contact);
    ConstructPhones(contact);
    ConstructRelation(contact);
    ConstructIms(contact);
    ConstructSipAddresses(contact);
    ConstructNickNames(contact);
    ConstructEmails(contact);
    ConstructPostals(contact);
    ConstructOrganizations(contact);
    ConstructWebsites(contact);
    ConstructPhotos(contact);
    ConstructNotes(contact);
    ConstructEvents(contact);
    ContactEnd();
    return result_.str();
}

void VCardConstructor::ContactBegin()
{
    AddLine(VCARD_TYPE_BEGIN, DATA_VCARD);
    if (VCardConfiguration::IsVer40(cardType_)) {
        AddLine(VCARD_TYPE_VERSION, VERSION_40);
    } else if (VCardConfiguration::IsVer30(cardType_)) {
        AddLine(VCARD_TYPE_VERSION, VERSION_30);
    } else {
        AddLine(VCARD_TYPE_VERSION, VERSION_21);
    }
    headLength_ = result_.str().length();
}

void VCardConstructor::ContactEnd()
{
    if (headLength_ == result_.str().length()) {
        TELEPHONY_LOGW("empty content");
        result_.str("");
        return;
    }
    AddLine(VCARD_TYPE_END, DATA_VCARD);
}

void VCardConstructor::SetPhoneNumberEncodedCallback(
    std::shared_ptr<PhoneNumberEncodedCallback> phoneNumberEncodedCallback)
{
    phoneNumberEncodedCallback_ = phoneNumberEncodedCallback;
}

bool VCardConstructor::IsNeedCharsetParam(std::vector<std::string> strs)
{
    if (!needCharsetParam_) {
        return false;
    }
    return !VCardUtils::IsWrapPrintableAscii(strs);
}

std::string VCardConstructor::FormatFullName(
    const std::string &givenName, const std::string &middleName, const std::string &familyName)
{
    std::ostringstream fullName;
    fullName << givenName;
    if (!middleName.empty()) {
        fullName << " " << middleName << ".";
    }
    fullName << " " << familyName;
    return fullName.str();
}

int32_t VCardConstructor::ConstructNameV40(std::shared_ptr<VCardContact> contact)
{
    auto nameDatas = contact->GetNames();
    if (nameDatas.empty()) {
        AddLine(VCARD_TYPE_FN, "");
        return TELEPHONY_SUCCESS;
    }
    auto nameData = nameDatas[0];
    if (nameData == nullptr) {
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::string familyName = nameData->GetFamily();
    std::string middleName = nameData->GetMiddle();
    std::string givenName = nameData->GetGiven();
    std::string prefix = nameData->GetPrefix();
    std::string suffix = nameData->GetSuffix();
    std::string formattedName = nameData->GetDisplayName();
    if (familyName.empty() && givenName.empty() && middleName.empty() && prefix.empty() && suffix.empty()) {
        if (formattedName.empty()) {
            AddLine(VCARD_TYPE_FN, "");
            return TELEPHONY_SUCCESS;
        }
        familyName = formattedName;
    }
    std::string phoneticFamilyName = nameData->GetPhoneticFamily();
    std::string phoneticMiddleName = nameData->GetPhoneticMiddle();
    std::string phoneticGivenName = nameData->GetPhoneticGiven();
    std::string escapedFamily = DealCharacters(familyName);
    std::string escapedGiven = DealCharacters(givenName);
    std::string escapedMiddle = DealCharacters(middleName);
    std::string escapedPrefix = DealCharacters(prefix);
    std::string escapedSuffix = DealCharacters(suffix);
    result_ << VCARD_TYPE_N;
    if (!(phoneticFamilyName.empty() && phoneticMiddleName.empty() && phoneticGivenName.empty())) {
        std::string sortAs = DealCharacters(phoneticFamilyName) + ';' + DealCharacters(phoneticGivenName) + ';' +
                             DealCharacters(phoneticMiddleName);
        result_ << PARAM_SEPARATOR << "SORT-AS=" << sortAs;
    }
    AddNameData(escapedFamily, escapedGiven, escapedMiddle, escapedPrefix, escapedSuffix);
    if (formattedName.empty()) {
        std::string name = DealCharacters(FormatFullName(givenName, middleName, familyName));
        AddLine(VCARD_TYPE_FN, name);
    } else {
        std::string formatted = DealCharacters(formattedName);
        result_ << VCARD_TYPE_FN;
        result_ << DATA_SEPARATOR << formatted;
        result_ << END_OF_LINE;
    }
    ConstructPhoneticNameFields(nameData);
    return TELEPHONY_SUCCESS;
}

void VCardConstructor::AddNameData(const std::string &family, const std::string &given, const std::string &middle,
    const std::string &prefix, const std::string &suffix)
{
    result_ << DATA_SEPARATOR << family;
    result_ << ITEM_SEPARATOR << given;
    result_ << ITEM_SEPARATOR << middle;
    result_ << ITEM_SEPARATOR << prefix;
    result_ << ITEM_SEPARATOR << suffix;
    result_ << END_OF_LINE;
}

int32_t VCardConstructor::ConstructPhoneticNameFields(std::shared_ptr<VCardNameData> nameData)
{
    std::string phoneticFamilyName = nameData->GetPhoneticFamily();
    std::string phoneticMiddleName = nameData->GetPhoneticMiddle();
    std::string phoneticGivenName = nameData->GetPhoneticGiven();
    if (phoneticFamilyName.empty() && phoneticMiddleName.empty() && phoneticGivenName.empty()) {
        return TELEPHONY_SUCCESS;
    }
    if (VCardConfiguration::IsVer30(cardType_)) {
        std::string fullName = FormatFullName(phoneticFamilyName, phoneticMiddleName, phoneticGivenName);
        result_ << VCARD_TYPE_SORT_STRING;
        if (IsNeedCharsetParam({ fullName })) {
            result_ << PARAM_SEPARATOR << charsetParam_;
        }
        result_ << DATA_SEPARATOR << DealCharacters(fullName);
        result_ << END_OF_LINE;
    }
    AddPhoneticName(VCARD_TYPE_X_PHONETIC_FIRST_NAME, phoneticGivenName);
    AddPhoneticName(VCARD_TYPE_X_PHONETIC_MIDDLE_NAME, phoneticMiddleName);
    AddPhoneticName(VCARD_TYPE_X_PHONETIC_LAST_NAME, phoneticFamilyName);
    return TELEPHONY_SUCCESS;
}

int32_t VCardConstructor::AddPhoneticName(const std::string &phoneticType, const std::string &phoneticName)
{
    if (phoneticName.empty()) {
        return TELEPHONY_SUCCESS;
    }
    bool needAddCharset = IsNeedCharsetParam({ phoneticName });
    bool needAddQuotedPrintable = needQP_ && !VCardUtils::IsPrintableAscii({ phoneticName });
    std::string encodedPhoneticName =
        (needAddQuotedPrintable ? EncodeQuotedPrintable(phoneticName) : DealCharacters(phoneticName));
    result_ << phoneticType;
    AddCharsetOrQuotedPrintable(needAddCharset, needAddQuotedPrintable);
    result_ << DATA_SEPARATOR << encodedPhoneticName;
    result_ << END_OF_LINE;
    return TELEPHONY_SUCCESS;
}

int32_t VCardConstructor::ConstructName(std::shared_ptr<VCardContact> contact)
{
    if (contact == nullptr) {
        TELEPHONY_LOGI("contact is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (VCardConfiguration::IsVer40(cardType_)) {
        return ConstructNameV40(contact);
    }

    auto nameDatas = contact->GetNames();
    if (nameDatas.empty()) {
        if (VCardConfiguration::IsVer30(cardType_)) {
            AddLine(VCARD_TYPE_N, "");
            AddLine(VCARD_TYPE_FN, "");
        }
        return TELEPHONY_SUCCESS;
    }

    auto nameData = nameDatas[0];
    if (nameData == nullptr) {
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::string familyName = nameData->GetFamily();
    std::string middleName = nameData->GetMiddle();
    std::string givenName = nameData->GetGiven();
    std::string prefix = nameData->GetPrefix();
    std::string suffix = nameData->GetSuffix();
    std::string displayName = nameData->GetDisplayName();

    if (!familyName.empty() || !givenName.empty()) {
        DealNoEmptyFimilyOrGivenName(familyName, givenName, middleName, prefix, suffix, displayName);
    } else if (!displayName.empty()) {
        AddSinglePartNameField(VCARD_TYPE_N, displayName);
        result_ << ITEM_SEPARATOR;
        result_ << ITEM_SEPARATOR;
        result_ << ITEM_SEPARATOR;
        result_ << ITEM_SEPARATOR;
        result_ << END_OF_LINE;
        AddSinglePartNameField(VCARD_TYPE_FN, displayName);
        result_ << END_OF_LINE;
    } else if (VCardConfiguration::IsVer30(cardType_)) {
        AddLine(VCARD_TYPE_N, "");
        AddLine(VCARD_TYPE_FN, "");
    } else {
        TELEPHONY_LOGI("No need to do anything");
    }
    ConstructPhoneticNameFields(nameData);
    return TELEPHONY_SUCCESS;
}

void VCardConstructor::DealNoEmptyFimilyOrGivenName(const std::string &familyName, const std::string &givenName,
    const std::string &middleName, const std::string &prefix, const std::string &suffix, const std::string &displayName)
{
    bool needAddCharset = IsNeedCharsetParam({ familyName, givenName, middleName, prefix, suffix });
    bool needAddQuotedPrintable =
        needQP_ && !VCardUtils::IsPrintableAscii({ familyName, givenName, middleName, prefix, suffix });
    std::string formattedName;
    if (!displayName.empty()) {
        formattedName = displayName;
    } else {
        formattedName = FormatFullName(givenName, middleName, familyName);
    }
    bool needAddCharsetToFN = IsNeedCharsetParam({ formattedName });
    bool needAddQuotedPrintableToFN = needQP_ && !VCardUtils::IsPrintableAscii({ formattedName });
    std::string encodedFamily =
        (needAddQuotedPrintable ? EncodeQuotedPrintable(familyName) : DealCharacters(familyName));
    std::string encodedGiven = (needAddQuotedPrintable ? EncodeQuotedPrintable(givenName) : DealCharacters(givenName));
    std::string encodedMiddle =
        (needAddQuotedPrintable ? EncodeQuotedPrintable(middleName) : DealCharacters(middleName));
    std::string encodedPrefix = (needAddQuotedPrintable ? EncodeQuotedPrintable(prefix) : DealCharacters(prefix));
    std::string encodedSuffix = (needAddQuotedPrintable ? EncodeQuotedPrintable(suffix) : DealCharacters(suffix));
    std::string encodedFormattedname =
        (needAddQuotedPrintableToFN ? EncodeQuotedPrintable(formattedName) : DealCharacters(formattedName));

    result_ << VCARD_TYPE_N;
    AddCharsetOrQuotedPrintable(needAddCharset, needAddQuotedPrintable);
    AddNameData(encodedFamily, encodedGiven, encodedMiddle, encodedPrefix, encodedSuffix);

    result_ << VCARD_TYPE_FN;
    AddCharsetOrQuotedPrintable(needAddCharsetToFN, needAddQuotedPrintableToFN);
    result_ << DATA_SEPARATOR << encodedFormattedname;
    result_ << END_OF_LINE;
}

void VCardConstructor::AddCharsetOrQuotedPrintable(bool needAddCharset, bool needAddQuotedPrintable)
{
    if (needAddCharset) {
        result_ << PARAM_SEPARATOR << charsetParam_;
    }
    if (needAddQuotedPrintable) {
        result_ << PARAM_SEPARATOR << PARAM_ENCODING_QP;
    }
}

void VCardConstructor::AddSinglePartNameField(std::string property, std::string part)
{
    bool needQuotedPrintable = needQP_ && !VCardUtils::IsPrintableAscii({ part });
    std::string encodedPart = needQuotedPrintable ? EncodeQuotedPrintable(part) : DealCharacters(part);
    result_ << property;
    AddCharsetOrQuotedPrintable(IsNeedCharsetParam({ part }), needQuotedPrintable);
    result_ << DATA_SEPARATOR << encodedPart;
}

int32_t VCardConstructor::ConstructPhones(std::shared_ptr<VCardContact> contact)
{
    if (contact == nullptr) {
        TELEPHONY_LOGI("contact is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    auto phoneDatas = contact->GetPhones();
    if (phoneDatas.empty()) {
        return TELEPHONY_SUCCESS;
    }
    std::set<std::string> phoneSet;
    for (auto data : phoneDatas) {
        if (data == nullptr) {
            continue;
        }
        std::string number = data->GetNumber();
        VCardUtils::Trim(number);
        if (number.empty()) {
            continue;
        }
        std::string labelId = data->GetLabelId();
        std::string labelName = data->GetLabelName();
        int32_t type = static_cast<int32_t>(PhoneVcType::NUM_HOME);
        if (VCardUtils::IsNum(labelId)) {
            type = std::stoi(labelId);
        }
        if (phoneNumberEncodedCallback_ != nullptr) {
            phoneNumberEncodedCallback_->onCallback(number, type, labelName, false);
        }

        auto it = phoneSet.find(number);
        if (it != phoneSet.end()) {
            continue;
        }
        phoneSet.insert(number);
        AddTelLine(labelId, labelName, number);
    }
    return TELEPHONY_SUCCESS;
}

int32_t VCardConstructor::ConstructRelation(std::shared_ptr<VCardContact> contact)
{
    if (contact == nullptr) {
        TELEPHONY_LOGI("contact is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    for (auto relationData : contact->GetRelations()) {
        if (relationData == nullptr) {
            continue;
        }
        AddCustomType(TypeData::RELATION,
            { relationData->GetRelationName(), relationData->GetLabelId(), relationData->GetLabelName() });
    }
    return TELEPHONY_SUCCESS;
}

void VCardConstructor::AddCustomType(const std::string &type, std::vector<std::string> values)
{
    bool needAddCharset = IsNeedCharsetParam(values);
    bool needAddQuotedPrintable = needQP_ && !VCardUtils::IsPrintableAscii(values);
    result_ << VCARD_TYPE_X_OHOS_CUSTOM;
    AddCharsetOrQuotedPrintable(needAddCharset, needAddQuotedPrintable);
    result_ << DATA_SEPARATOR << type;
    for (auto value : values) {
        std::string encodedValue = needAddQuotedPrintable ? EncodeQuotedPrintable(value) : DealCharacters(value);
        result_ << ITEM_SEPARATOR << encodedValue;
    }
    result_ << END_OF_LINE;
}

int32_t VCardConstructor::ConstructIms(std::shared_ptr<VCardContact> contact)
{
    if (contact == nullptr) {
        TELEPHONY_LOGI("contact is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    for (auto imsData : contact->GetIms()) {
        if (imsData == nullptr) {
            continue;
        }
        auto labelId = imsData->GetLabelId();
        auto type = VCardUtils::GetTypeFromImLabelId(labelId);
        if (type.empty()) {
            continue;
        }
        AddLineWithCharsetAndQP(type, { imsData->GetAddress() });
    }
    return TELEPHONY_SUCCESS;
}

int32_t VCardConstructor::ConstructSipAddresses(std::shared_ptr<VCardContact> contact)
{
    if (contact == nullptr) {
        TELEPHONY_LOGI("contact is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    for (auto sipData : contact->GetSips()) {
        if (sipData == nullptr) {
            continue;
        }
        auto address = sipData->GetAddress();
        if (address.empty()) {
            continue;
        }
        if (!VCardUtils::StartWith(address, "sip:")) {
            address = "sip:" + address;
        }
        auto type = std::string(VCARD_TYPE_X_SIP);
        if (VCardConfiguration::IsVer40(cardType_)) {
            type = VCARD_TYPE_IMPP;
        }
        AddLineWithCharsetAndQP(type, { address, sipData->GetLabelId(), sipData->GetLabelName() });
    }
    return TELEPHONY_SUCCESS;
}

int32_t VCardConstructor::ConstructNickNames(std::shared_ptr<VCardContact> contact)
{
    if (contact == nullptr) {
        TELEPHONY_LOGI("contact is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    for (auto nicknameData : contact->GetNicknames()) {
        if (nicknameData == nullptr) {
            continue;
        }
        if (nicknameData->GetNickName().empty()) {
            continue;
        }
        AddCustomType(TypeData::NICKNAME, { nicknameData->GetNickName() });
    }
    return TELEPHONY_SUCCESS;
}

int32_t VCardConstructor::ConstructEmails(std::shared_ptr<VCardContact> contact)
{
    if (contact == nullptr) {
        TELEPHONY_LOGI("contact is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    std::set<std::string> emailSet;
    for (auto data : contact->GetEmails()) {
        std::string email = data->GetAddress();
        VCardUtils::Trim(email);
        if (email.empty()) {
            continue;
        }
        int32_t labelId = static_cast<int32_t>(EmailType::EMAIL_OTHER);
        std::string labelIdStr = data->GetLabelId();
        if (!labelIdStr.empty() && VCardUtils::IsNum(labelIdStr)) {
            labelId = std::stoi(labelIdStr);
        }
        auto it = emailSet.find(email);
        if (it != emailSet.end()) {
            continue;
        }
        AddEmailLine(labelId, data->GetLabelName(), email, data->GetDisplayName());
        emailSet.insert(email);
    }
    return TELEPHONY_SUCCESS;
}

int32_t VCardConstructor::ConstructPostals(std::shared_ptr<VCardContact> contact)
{
    if (contact == nullptr) {
        TELEPHONY_LOGI("contact is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    for (auto data : contact->GetPostalDatas()) {
        if (data == nullptr) {
            continue;
        }
        int32_t labelId = static_cast<int32_t>(PostalType::ADDR_HOME);
        if (VCardUtils::IsNum(data->GetLabelId())) {
            labelId = std::stoi(data->GetLabelId());
        }
        AddPostalLine(data, labelId, data->GetLabelName());
    }
    return TELEPHONY_SUCCESS;
}

void VCardConstructor::AddPostalLine(
    std::shared_ptr<VCardPostalData> postalData, int32_t postalType, const std::string &labelName)
{
    bool needCharset = false;
    bool needAddQuotedPrintable = false;
    std::stringstream postalLine;
    ConstructPostalLine(postalData, postalLine, needCharset, needAddQuotedPrintable);
    if (postalLine.str().empty()) {
        return;
    }
    std::vector<std::string> paramTypes;
    std::string postalTypeStr = "";
    if (postalType == static_cast<int32_t>(PostalType::ADDR_HOME)) {
        postalTypeStr = VCARD_PARAM_TYPE_HOME;
    }
    if (postalType == static_cast<int32_t>(PostalType::ADDR_WORK)) {
        postalTypeStr = VCARD_PARAM_TYPE_WORK;
    }
    if (postalType == static_cast<int32_t>(PostalType::CUSTOM_LABEL)) {
        postalTypeStr = "X-" + labelName;
    }
    if (postalType == static_cast<int32_t>(PostalType::ADDR_OTHER)) {
        postalTypeStr = "X-" + std::string(VCARD_PARAM_ADR_EXTRA_TYPE_OTHER);
    }
    if (!postalTypeStr.empty()) {
        paramTypes.push_back(postalTypeStr);
    }
    result_ << VCARD_TYPE_ADR;
    if (!paramTypes.empty()) {
        result_ << PARAM_SEPARATOR;
        AddParamTypes(paramTypes);
    }
    AddCharsetOrQuotedPrintable(needCharset, needAddQuotedPrintable);
    result_ << DATA_SEPARATOR;
    result_ << postalLine.str() << END_OF_LINE;
}

void VCardConstructor::ConstructPostalLine(std::shared_ptr<VCardPostalData> postalData, std::stringstream &postalLine,
    bool &needCharset, bool &needAddQuotedPrintable)
{
    std::string poBox = postalData->GetPOBox();
    std::string street = postalData->GetStreet();
    std::string city = postalData->GetCity();
    std::string region = postalData->GetRegion();
    std::string postalCode = postalData->GetPostCode();
    std::string country = postalData->GetCountry();
    std::vector<std::string> addresses = { poBox, street, city, region, postalCode, country };
    if (!VCardUtils::IsAllEmpty(addresses)) {
        needAddQuotedPrintable = needQP_ && !VCardUtils::IsPrintableAscii(addresses);
        needCharset = !VCardUtils::IsWrapPrintableAscii({ addresses });
        std::string encodedPoBox = (needAddQuotedPrintable ? EncodeQuotedPrintable(poBox) : DealCharacters(poBox));
        std::string encodedStreet = (needAddQuotedPrintable ? EncodeQuotedPrintable(street) : DealCharacters(street));
        std::string encodedCity = (needAddQuotedPrintable ? EncodeQuotedPrintable(city) : DealCharacters(city));
        std::string encodedRegion = (needAddQuotedPrintable ? EncodeQuotedPrintable(region) : DealCharacters(region));
        std::string encodedPostalCode =
            (needAddQuotedPrintable ? EncodeQuotedPrintable(postalCode) : DealCharacters(postalCode));
        std::string encodedCountry =
            (needAddQuotedPrintable ? EncodeQuotedPrintable(country) : DealCharacters(country));
        postalLine << encodedPoBox << ITEM_SEPARATOR << ITEM_SEPARATOR;
        postalLine << encodedStreet << ITEM_SEPARATOR;
        postalLine << encodedCity << ITEM_SEPARATOR;
        postalLine << encodedRegion << ITEM_SEPARATOR;
        postalLine << encodedPostalCode << ITEM_SEPARATOR;
        postalLine << encodedCountry;
        return;
    }
    auto postalAddress = postalData->GetPostalAddress();
    if (postalAddress.empty()) {
        return;
    }
    needAddQuotedPrintable = needQP_ && !VCardUtils::IsPrintableAscii({ postalAddress });
    needCharset = IsNeedCharsetParam({ postalAddress });
    std::string encodedPostalAddress =
        (needAddQuotedPrintable ? EncodeQuotedPrintable(postalAddress) : DealCharacters(postalAddress));
    postalLine << ITEM_SEPARATOR;
    postalLine << encodedPostalAddress;
    postalLine << ITEM_SEPARATOR;
    postalLine << ITEM_SEPARATOR;
    postalLine << ITEM_SEPARATOR;
    postalLine << ITEM_SEPARATOR;
    postalLine << ITEM_SEPARATOR;
}

int32_t VCardConstructor::ConstructOrganizations(std::shared_ptr<VCardContact> contact)
{
    if (contact == nullptr) {
        TELEPHONY_LOGI("contact is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    for (auto organizationData : contact->GetOrganizations()) {
        if (organizationData == nullptr) {
            continue;
        }
        std::string company = organizationData->GetCompany();
        std::string orgLine = "";
        VCardUtils::Trim(company);
        if (!company.empty()) {
            orgLine += company;
        }
        AddLine(VCARD_TYPE_ORG, orgLine, !VCardUtils::IsWrapPrintableAscii({ orgLine }),
            needQP_ && !VCardUtils::IsPrintableAscii({ orgLine }));
        std::string title = organizationData->GetTitle();
        VCardUtils::Trim(title);
        if (!title.empty()) {
            AddLine(VCARD_TYPE_TITLE, title, !VCardUtils::IsWrapPrintableAscii({ title }),
                needQP_ && !VCardUtils::IsPrintableAscii({ title }));
        }
    }
    return TELEPHONY_SUCCESS;
}

int32_t VCardConstructor::ConstructWebsites(std::shared_ptr<VCardContact> contact)
{
    if (contact == nullptr) {
        TELEPHONY_LOGI("contact is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    for (auto websiteData : contact->GetWebsites()) {
        if (websiteData == nullptr) {
            continue;
        }
        auto website = websiteData->GetWebsite();
        VCardUtils::Trim(website);
        if (website.empty()) {
            continue;
        }
        AddLineWithCharsetAndQP(VCARD_TYPE_URL, { website, websiteData->GetLabelId(), websiteData->GetLabelName() });
    }
    return TELEPHONY_SUCCESS;
}

int32_t VCardConstructor::ConstructPhotos(std::shared_ptr<VCardContact> contact)
{
    if (contact == nullptr) {
        TELEPHONY_LOGI("contact is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    for (auto photoData : contact->GetPhotos()) {
        if (photoData == nullptr) {
            continue;
        }
        auto bytes = photoData->GetBytes();
        if (bytes.empty()) {
            continue;
        }
        auto phoneType = VCardUtils::GetImageType(bytes);
        if (phoneType.empty()) {
            continue;
        }
        auto encodeValue = VCardUtils::EncodeBase64(bytes);
        if (encodeValue.empty()) {
            continue;
        }
        AddPhotoLine(encodeValue, phoneType);
    }
    return TELEPHONY_SUCCESS;
}

int32_t VCardConstructor::ConstructNotes(std::shared_ptr<VCardContact> contact)
{
    if (contact == nullptr) {
        TELEPHONY_LOGI("contact is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    for (auto noteData : contact->GetNotes()) {
        if (noteData == nullptr) {
            continue;
        }
        auto note = noteData->GetNote();
        VCardUtils::Trim(note);
        if (note.empty()) {
            continue;
        }
        AddLineWithCharsetAndQP(VCARD_TYPE_NOTE, { note });
    }
    return TELEPHONY_SUCCESS;
}

int32_t VCardConstructor::ConstructEvents(std::shared_ptr<VCardContact> contact)
{
    if (contact == nullptr) {
        TELEPHONY_LOGI("contact is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::string birthdayDate = "";
    for (auto eventData : contact->GetEventDatas()) {
        if (eventData == nullptr) {
            continue;
        }
        int32_t labelId = static_cast<int32_t>(EventType::EVENT_OTHER);
        if (VCardUtils::IsNum(eventData->GetLabelId())) {
            labelId = std::stoi(eventData->GetLabelId());
        }
        if (labelId == static_cast<int32_t>(EventType::EVENT_BIRTHDAY)) {
            if (eventData->GetEventDate().empty()) {
                continue;
            }
            birthdayDate = eventData->GetEventDate();
            continue;
        }
        AddCustomType(
            TypeData::CONTACT_EVENT, { eventData->GetEventDate(), eventData->GetLabelId(), eventData->GetLabelName() });
    }
    VCardUtils::Trim(birthdayDate);
    if (!birthdayDate.empty()) {
        AddLineWithCharsetAndQP(VCARD_TYPE_BDAY, { birthdayDate });
    }
    return TELEPHONY_SUCCESS;
}

void VCardConstructor::AddTelLine(const std::string &labelId, const std::string &labelName, const std::string &number)
{
    result_ << VCARD_TYPE_TEL << PARAM_SEPARATOR;
    auto paramTypes = VCardUtils::GetTypeFromPhoneLabelId(labelId);
    if (!paramTypes.empty()) {
        AddParamTypes(paramTypes);
    } else if (VCardUtils::IsNum(labelId)) {
        auto phoneType = static_cast<PhoneVcType>(std::stoi(labelId));
        if (phoneType == PhoneVcType::CUSTOM_LABEL) {
            paramTypes.push_back("X-" + labelName);
            AddParamTypes(paramTypes);
        }
    }
    result_ << DATA_SEPARATOR << number;
    result_ << END_OF_LINE;
}

void VCardConstructor::AddPhotoLine(const std::string &encodedValue, const std::string &photoType)
{
    std::stringstream photoLine;
    photoLine << VCARD_TYPE_PHOTO << PARAM_SEPARATOR;
    if (isV30OrV40_) {
        photoLine << PARAM_ENCODING_BASE64_AS_B;
    } else {
        photoLine << PARAM_ENCODING_BASE64_V21;
    }
    photoLine << PARAM_SEPARATOR;
    AddParamType(photoLine, photoType);
    photoLine << DATA_SEPARATOR;
    photoLine << encodedValue;

    std::string tmpStr = photoLine.str();
    photoLine.str("");
    photoLine.clear();
    int32_t count = 0;
    int32_t length = static_cast<int32_t>(tmpStr.length());
    int32_t firstLineNum = MAX_LINE_NUMS_BASE64_V30 - static_cast<int32_t>(std::string(END_OF_LINE).length());
    int32_t generalLineNum = firstLineNum - static_cast<int32_t>(std::string(WS).length());
    int32_t maxNum = firstLineNum;
    for (int32_t i = 0; i < length; i++) {
        photoLine << tmpStr[i];
        count++;
        if (count <= maxNum) {
            continue;
        }
        photoLine << END_OF_LINE << WS;
        maxNum = generalLineNum;
        count = 0;
    }
    result_ << photoLine.str() << END_OF_LINE << END_OF_LINE;
}

void VCardConstructor::AddEmailLine(
    int32_t emailType, const std::string &labelName, const std::string &email, const std::string &displayName)
{
    std::vector<std::string> paramTypes;
    std::string postalTypeStr = "";
    if (emailType == static_cast<int32_t>(EmailType::EMAIL_HOME)) {
        postalTypeStr = VCARD_PARAM_TYPE_HOME;
    }
    if (emailType == static_cast<int32_t>(EmailType::EMAIL_WORK)) {
        postalTypeStr = VCARD_PARAM_TYPE_WORK;
    }
    if (emailType == static_cast<int32_t>(EmailType::CUSTOM_LABEL)) {
        postalTypeStr = "X-" + labelName;
    }
    if (!postalTypeStr.empty()) {
        paramTypes.push_back(postalTypeStr);
    }
    std::vector<std::string> valueList = { email, displayName };
    bool needAddCharset = IsNeedCharsetParam(valueList);
    bool needAddQuotedPrintable = needQP_ && !VCardUtils::IsPrintableAscii(valueList);
    AddLine(VCARD_TYPE_EMAIL, paramTypes, valueList, needAddCharset, needAddQuotedPrintable);
}

void VCardConstructor::AddLine(const std::string &type, const std::string &rawValue)
{
    AddLine(type, rawValue, false, false);
}

void VCardConstructor::AddLine(const std::string &type, std::vector<std::string> valueList)
{
    AddLine(type, valueList, false, false);
}

void VCardConstructor::AddLine(
    const std::string &type, const std::string &rawValue, bool needCharset, bool needQuotedPrintable)
{
    AddLine(type, {}, rawValue, needCharset, needQuotedPrintable);
}

void VCardConstructor::AddLine(
    const std::string &type, const std::vector<std::string> &paramList, const std::string &rawValue)
{
    AddLine(type, paramList, rawValue, false, false);
}

void VCardConstructor::AddLine(const std::string &type, const std::vector<std::string> &paramList,
    const std::string &rawValue, bool needCharset, bool needQuotedPrintable)
{
    result_ << type;
    if (paramList.size() > 0) {
        result_ << PARAM_SEPARATOR;
        AddParamTypes(paramList);
    }
    std::string encodedValue = needQuotedPrintable ? EncodeQuotedPrintable(rawValue) : DealCharacters(rawValue);
    AddCharsetOrQuotedPrintable(needCharset, needQuotedPrintable);
    result_ << DATA_SEPARATOR;
    result_ << encodedValue;
    result_ << END_OF_LINE;
}
void VCardConstructor::AddLineWithCharsetAndQP(const std::string &type, std::vector<std::string> valueList)
{
    bool needAddCharset = IsNeedCharsetParam(valueList);
    bool needAddQuotedPrintable = needQP_ && !VCardUtils::IsPrintableAscii({ valueList });
    AddLine(type, valueList, needAddCharset, needAddQuotedPrintable);
}

void VCardConstructor::AddLine(
    const std::string &type, std::vector<std::string> valueList, bool needCharset, bool needQuotedPrintable)
{
    AddLine(type, {}, valueList, needCharset, needQuotedPrintable);
}

void VCardConstructor::AddLine(const std::string &type, const std::vector<std::string> &paramList,
    std::vector<std::string> valueList, bool needCharset, bool needQuotedPrintable)
{
    result_ << type;
    if (paramList.size() > 0) {
        result_ << PARAM_SEPARATOR;
        AddParamTypes(paramList);
    }
    AddCharsetOrQuotedPrintable(needCharset, needQuotedPrintable);

    result_ << DATA_SEPARATOR;
    bool first = true;
    for (std::string rawValue : valueList) {
        std::string encodedValue;
        if (needQuotedPrintable) {
            encodedValue = EncodeQuotedPrintable(rawValue);
        } else {
            encodedValue = DealCharacters(rawValue);
        }

        if (first) {
            first = false;
        } else {
            result_ << ITEM_SEPARATOR;
        }
        result_ << encodedValue;
    }
    result_ << END_OF_LINE;
}

void VCardConstructor::HandleCharacter(int i, int32_t length, std::string value, std::string &temp)
{
    auto ch = value[i];
    switch (ch) {
        case ';': {
            temp += "\\;";
            break;
        }
        case '\r': {
            if (i + 1 < length) {
                auto nextChar = value[i + 1];
                if (nextChar == '\n') {
                    break;
                }
            }
            // fall_through
        }
        case '\n': {
            temp += "\\n";
            break;
        }
        case '\\': {
            if (isV30OrV40_) {
                temp += "\\\\";
                break;
            }
            // fall_through
        }
        case ',': {
            if (isV30OrV40_) {
                temp += "\\,";
            } else {
                temp += ch;
            }
            break;
        }
        default: {
            temp += ch;
            break;
        }
    }
}

std::string VCardConstructor::DealCharacters(std::string value)
{
    if (value.empty()) {
        return "";
    }

    std::string temp;
    int32_t length = value.length();
    for (int32_t i = 0; i < length; i++) {
        HandleCharacter(i, length, value, temp);
    }
    return temp;
}

std::string VCardConstructor::EncodeQuotedPrintable(const std::string &input)
{
    std::ostringstream encodedStream;
    int32_t lineCount = 0;
    int32_t maxLen = ENCODEN_QUOTED_PRIN_MAX_LEN;
    for (auto ch : input) {
        encodedStream << "=" << std::uppercase << std::setw(VALUE_INDEX_TWO) << std::setfill('0') << std::hex
                      << static_cast<int32_t>(ch);
        lineCount += VALUE_LEN_THREE;
        if (lineCount >= maxLen) {
            encodedStream << "=\r\n";
            lineCount = 0;
        }
    }

    return encodedStream.str();
}

void VCardConstructor::AddParamTypes(std::vector<std::string> types)
{
    if (VCardConfiguration::IsVer40(cardType_) || VCardConfiguration::IsVer30(cardType_)) {
        if (types.empty()) {
            return;
        }
        bool first = true;
        for (auto typeValue : types) {
            if (first) {
                first = false;
                AddParamType(typeValue);
            } else {
                result_ << PARAM_SEPARATOR_V3_V4 << typeValue;
            }
        }
        return;
    }
    bool first = true;
    for (auto typeValue : types) {
        if (first) {
            first = false;
        } else {
            result_ << PARAM_SEPARATOR;
        }
        AddParamType(typeValue);
    }
}

void VCardConstructor::AddParamType(const std::string &paramType)
{
    AddParamType(result_, paramType);
}

void VCardConstructor::AddParamType(std::stringstream &result, const std::string &paramType)
{
    if (VCardConfiguration::IsVer40(cardType_) || VCardConfiguration::IsVer30(cardType_)) {
        result << VCARD_PARAM_TYPE;
        result << PARAM_EQUAL;
    }
    result << paramType;
}

std::string VCardConstructor::ToString()
{
    return result_.str();
}

} // namespace Telephony
} // namespace OHOS
