/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "vcard_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#define protected public
#include <fstream>
#include <sstream>

#include "addcoreservicetoken_fuzzer.h"
#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "event_runner.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "vcard_constructor.h"
#include "vcard_manager.h"
#include "vcard_utils.h"
#include "fuzzer/FuzzedDataProvider.h"

using namespace OHOS::Telephony;
namespace OHOS {
constexpr const char *FILE_NAME = "example.vcf";
constexpr int32_t TYPE_NUM = 3;

void WriteTestData(const std::string &testStr)
{
    std::ofstream file;
    file.open(FILE_NAME, std::ios::out);
    if (file.is_open()) {
        std::stringstream ss(testStr);
        std::string line;

        while (std::getline(ss, line)) {
            file << line << std::endl;
        }
    }
    file.close();
}

void DecodeVcard(std::shared_ptr<FuzzedDataProvider> provider)
{
    if (provider == nullptr) {
        return;
    }
    std::string inputString = R"(
BEGIN:VCARD
VERSION:2.0
N;CHARSET=UTF-8:刘;小;;;
EMAIL;TYPE=WORK:test@example.com
EMAIL;TYPE=HOME:home@example.com
EMAIL;TYPE=INTERNET:email@example.com
EMAIL;TYPE=PREF:preferred@example.com
EMAIL;TYPE=X-CUSTOM:custom@example.com
EMAIL;INTERNET:"llll"
 <test@example.com>
END:VCARD
)";
    WriteTestData(inputString);
    int32_t errorCode = provider->ConsumeIntegral<int32_t>() % TYPE_NUM;
    VCardManager::GetInstance().Decode(FILE_NAME, errorCode);
}

void DecodeVcardNull01(std::shared_ptr<FuzzedDataProvider> provider)
{
    if (provider == nullptr) {
        return;
    }
    std::string inputString = R"(
BEGIN:VCARD
VERSION:3.0
PRODID:-//Apple Inc.//iPhone OS 18.5//EN
N:;Ella2;;;
FN:Ella2
TEL;VOICE:397472181
UID:F6FBE71F6A8347B8828EA5075CA58B36
END:VCARD

BEGIN:VCARD
VERSION:3.0
PRODID:-//Apple Inc.//iPhone OS 18.5//EN
N:;Ivey7;;;
FN:Ivey7
TEL:2028717726
TEL;VOICE:198290471
TEL:1966159148
TEL:406591947
UID:BB41F8F492B5432AA679C1F9DA5713CF
END:VCARD

)";
    WriteTestData(inputString);
    int32_t errorCode = provider->ConsumeIntegral<int32_t>() % TYPE_NUM;
    VCardManager::GetInstance().Decode(FILE_NAME, errorCode);
}

void DecodeVcardNull02(std::shared_ptr<FuzzedDataProvider> provider)
{
    if (provider == nullptr) {
        return;
    }
    std::string inputString = R"(
 
)";
    WriteTestData(inputString);
    int32_t errorCode = provider->ConsumeIntegral<int32_t>() % TYPE_NUM;
    VCardManager::GetInstance().Decode(FILE_NAME, errorCode);
}

void DecodeVcardData(std::shared_ptr<FuzzedDataProvider> provider)
{
    if (provider == nullptr) {
        return;
    }
    std::string fuzzdata = provider->ConsumeRandomLengthString();
    std::string inputString = R"(
BEGIN:VCARD
VERSION:2.0
N;CHARSET=UTF-8:刘;小;;;
EMAIL;TYPE=WORK:test@example.com
EMAIL;TYPE=HOME:home@example.com
EMAIL;TYPE=INTERNET:email@example.com
EMAIL;TYPE=PREF:preferred@example.com
EMAIL;TYPE=X-CUSTOM:custom@example.com
EMAIL;INTERNET:"llll"
 <test@example.com>
END:VCARD
)" + fuzzdata;
    WriteTestData(inputString);
    int32_t errorCode = provider->ConsumeIntegral<int32_t>() % TYPE_NUM;
    VCardManager::GetInstance().Decode(FILE_NAME, errorCode);
}

void DecodeVcardRelation(std::shared_ptr<FuzzedDataProvider> provider)
{
    if (provider == nullptr) {
        return;
    }
    std::string inputString =
        "BEGIN:VCARD\r\nVERSION:2.1\r\nX_OHOS_CUSTOM;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:relation;="
        "E6=B5=8B=E8=AF=95;=E6=B5=8B=E8=AF=95=69=64;=E6=B5=8B=E8=AF=95=6E=61=6D=65\r\nX_OHOS_CUSTOM:"
        "relation;realationName;labelId;labelName\r\nEND:VCARD\r\n";
    WriteTestData(inputString);
    int32_t errorCode = provider->ConsumeIntegral<int32_t>() % TYPE_NUM;
    VCardManager::GetInstance().Decode(FILE_NAME, errorCode);
}

void DecodeVcardRelationData(std::shared_ptr<FuzzedDataProvider> provider)
{
    if (provider == nullptr) {
        return;
    }
    std::string fuzzdata = provider->ConsumeRandomLengthString();
    std::string inputString =
        "BEGIN:VCARD\r\nVERSION:2.1\r\nX_OHOS_CUSTOM;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:relation;="
        "E6=B5=8B=E8=AF=95;=E6=B5=8B=E8=AF=95=69=64;=E6=B5=8B=E8=AF=95=6E=61=6D=65\r\nX_OHOS_CUSTOM:"
        "relation;realationName;labelId;labelName\r\nEND:VCARD\r\n" +
        fuzzdata;
    WriteTestData(inputString);
    int32_t errorCode = provider->ConsumeIntegral<int32_t>() % TYPE_NUM;
    VCardManager::GetInstance().Decode(FILE_NAME, errorCode);
}

void ContructName(std::shared_ptr<FuzzedDataProvider> provider)
{
    if (provider == nullptr) {
        return;
    }
    auto nameData = std::make_shared<VCardNameData>();
    std::string displayName = provider->ConsumeRandomLengthString();
    nameData->displayName_ = displayName;
    nameData->family_ = "测试F";
    nameData->given_ = "wowowo";
    nameData->middle_ = "测试M";
    nameData->suffix_ = "wowowoSu";
    nameData->prefix_ = "测试P";
    nameData->phoneticFamily_ = "测试FP";
    nameData->phoneticGiven_ = "测试GV";
    nameData->phoneticMiddle_ = "wowowowMI";
    auto contact = std::make_shared<VCardContact>();
    contact->names_.push_back(nameData);
    auto constructor = std::make_shared<VCardConstructor>();
    auto value = constructor->ContactVCard(contact);
}

void ContructNameData(std::shared_ptr<FuzzedDataProvider> provider)
{
    if (provider == nullptr) {
        return;
    }
    auto nameData = std::make_shared<VCardNameData>();
    std::string displayName = provider->ConsumeRandomLengthString();
    nameData->displayName_ = displayName;
    std::string family = provider->ConsumeRandomLengthString();
    nameData->family_ = family;
    std::string given = provider->ConsumeRandomLengthString();
    nameData->given_ = given;
    std::string middle = provider->ConsumeRandomLengthString();
    nameData->middle_ = middle;
    std::string suffix = provider->ConsumeRandomLengthString();
    nameData->suffix_ = suffix;
    std::string prefix = provider->ConsumeRandomLengthString();
    nameData->prefix_ = prefix;
    std::string phoneticFamily = provider->ConsumeRandomLengthString();
    nameData->phoneticFamily_ = phoneticFamily;
    std::string phoneticGiven = provider->ConsumeRandomLengthString();
    nameData->phoneticGiven_ = phoneticGiven;
    std::string phoneticMiddle = provider->ConsumeRandomLengthString();
    nameData->phoneticMiddle_ = phoneticMiddle;
    auto contact = std::make_shared<VCardContact>();
    contact->names_.push_back(nameData);
    auto constructor = std::make_shared<VCardConstructor>();
    auto value = constructor->ContactVCard(contact);
}

void ContructRelation(std::shared_ptr<FuzzedDataProvider> provider)
{
    if (provider == nullptr) {
        return;
    }
    auto data1 = std::make_shared<VCardRelationData>();
    std::string test = provider->ConsumeRandomLengthString();
    data1->relationName_ = test;
    data1->labelId_ = "测试id";
    data1->labelName_ = "测试name";
    auto data2 = std::make_shared<VCardRelationData>();
    data2->relationName_ = "realationName";
    data2->labelId_ = "labelId";
    data2->labelName_ = "labelName";
    auto contact = std::make_shared<VCardContact>();
    contact->relations_.push_back(data1);
    contact->relations_.push_back(data2);
    auto constructor = std::make_shared<VCardConstructor>();
    auto value = constructor->ContactVCard(contact);
}

void ContructRelationData(std::shared_ptr<FuzzedDataProvider> provider)
{
    if (provider == nullptr) {
        return;
    }
    auto data1 = std::make_shared<VCardRelationData>();
    std::string test = provider->ConsumeRandomLengthString();
    data1->relationName_ = test;
    std::string testId = provider->ConsumeRandomLengthString();
    data1->labelId_ = testId;
    std::string testName = provider->ConsumeRandomLengthString();
    data1->labelName_ = testName;
    auto data2 = std::make_shared<VCardRelationData>();
    std::string realationName = provider->ConsumeRandomLengthString();
    data2->relationName_ = realationName;
    std::string labelId = provider->ConsumeRandomLengthString();
    data2->labelId_ = labelId;
    std::string labelName = provider->ConsumeRandomLengthString();
    data2->labelName_ = labelName;
    auto contact = std::make_shared<VCardContact>();
    contact->relations_.push_back(data1);
    contact->relations_.push_back(data2);
    auto constructor = std::make_shared<VCardConstructor>();
    auto value = constructor->ContactVCard(contact);
}

void DecodeVcardRelationV30(std::shared_ptr<FuzzedDataProvider> provider)
{
    if (provider == nullptr) {
        return;
    }
    std::string inputString = "BEGIN:VCARD\r\nVERSION:3.0\r\nN:\r\nFN:\r\nTEL;TYPE=HOME:1202020\r\nTEL;TYPE=WORK,FAX:"
                              "49305484\r\nTEL;TYPE=X-Work:503330303030\r\nEND:VCARD\r\n";
    WriteTestData(inputString);
    int32_t errorCode = provider->ConsumeIntegral<int32_t>() % TYPE_NUM;
    VCardManager::GetInstance().Decode(FILE_NAME, errorCode);
}

void DecodeVcardRelationDataV30(std::shared_ptr<FuzzedDataProvider> provider)
{
    if (provider == nullptr) {
        return;
    }
    std::string fuzzdata = provider->ConsumeRandomLengthString();
    std::string inputString = "BEGIN:VCARD\r\nVERSION:3.0\r\nN:\r\nFN:\r\nTEL;TYPE=HOME:1202020\r\nTEL;TYPE=WORK,FAX:"
                              "49305484\r\nTEL;TYPE=X-Work:503330303030\r\nEND:VCARD\r\n" +
                              fuzzdata;
    WriteTestData(inputString);
    int32_t errorCode = provider->ConsumeIntegral<int32_t>() % TYPE_NUM;
    VCardManager::GetInstance().Decode(FILE_NAME, errorCode);
}

void DecodeVcardRelationV40(std::shared_ptr<FuzzedDataProvider> provider)
{
    if (provider == nullptr) {
        return;
    }
    std::string inputString =
        "BEGIN:VCARD\r\nVERSION:4.0\r\nN:test1;;;;\r\nFN:test1\r\nEND:VCARD\r\nBEGIN:VCARD\r\nVERSION:4.0\r\nN:test2;;;"
        ";\r\nFN:test2\r\nEND:VCARD\r\nBEGIN:VCARD\r\nVERSION:4.0\r\nN:test3;;;;\r\nFN:test3\r\nEND:VCARD\r\n";
    WriteTestData(inputString);
    int32_t errorCode = provider->ConsumeIntegral<int32_t>() % TYPE_NUM;
    VCardManager::GetInstance().Decode(FILE_NAME, errorCode);
}

void DecodeVcardRelationDataV40(std::shared_ptr<FuzzedDataProvider> provider)
{
    if (provider == nullptr) {
        return;
    }
    std::string fuzzdata = provider->ConsumeRandomLengthString();
    std::string inputString =
        "BEGIN:VCARD\r\nVERSION:4.0\r\nN:test1;;;;\r\nFN:test1\r\nEND:VCARD\r\nBEGIN:VCARD\r\nVERSION:4.0\r\nN:test2;;;"
        ";\r\nFN:test2\r\nEND:VCARD\r\nBEGIN:VCARD\r\nVERSION:4.0\r\nN:test3;;;;\r\nFN:test3\r\nEND:VCARD\r\n" +
        fuzzdata;
    WriteTestData(inputString);
    int32_t errorCode = provider->ConsumeIntegral<int32_t>() % TYPE_NUM;
    VCardManager::GetInstance().Decode(FILE_NAME, errorCode);
}

void Import(std::shared_ptr<FuzzedDataProvider> provider)
{
    if (provider == nullptr) {
        return;
    }
    std::string fuzzdata = provider->ConsumeRandomLengthString();
    int32_t accountId = provider->ConsumeIntegral<int32_t>();
    VCardManager::GetInstance().Import(fuzzdata, accountId);
}

void ImportLock(std::shared_ptr<FuzzedDataProvider> provider)
{
    if (provider == nullptr) {
        return;
    }
    std::string fuzzdata = provider->ConsumeRandomLengthString();
    int32_t accountId = provider->ConsumeIntegral<int32_t>();
    VCardManager::GetInstance().ImportLock(fuzzdata, nullptr, accountId);
}

void Export(std::shared_ptr<FuzzedDataProvider> provider)
{
    if (provider == nullptr) {
        return;
    }
    std::string fuzzdata = provider->ConsumeRandomLengthString();
    DataShare::DataSharePredicates predicates;
    predicates.Between(Contact::ID, "0", "10");
    int32_t cardType = provider->ConsumeIntegral<int32_t>() % TYPE_NUM;
    VCardManager::GetInstance().Export(fuzzdata, predicates, cardType);
}

void ExportLock(std::shared_ptr<FuzzedDataProvider> provider)
{
    if (provider == nullptr) {
        return;
    }
    std::string fuzzdata = provider->ConsumeRandomLengthString();
    DataShare::DataSharePredicates predicates;
    predicates.Between(Contact::ID, "0", "10");
    int32_t cardType = provider->ConsumeIntegral<int32_t>() % TYPE_NUM;
    VCardManager::GetInstance().ExportLock(fuzzdata, nullptr, predicates, cardType);
}

void ExportToStr(std::shared_ptr<FuzzedDataProvider> provider)
{
    if (provider == nullptr) {
        return;
    }
    std::string fuzzdata = provider->ConsumeRandomLengthString();
    DataShare::DataSharePredicates predicates;
    predicates.Between(Contact::ID, "0", "10");
    int32_t cardType = provider->ConsumeIntegral<int32_t>() % TYPE_NUM;
    VCardManager::GetInstance().ExportToStr(fuzzdata, predicates, cardType);
    VCardManager::GetInstance().SetDataHelper(nullptr);
}

void VCardUtilsTest(std::shared_ptr<FuzzedDataProvider> provider)
{
    if (provider == nullptr) {
        return;
    }
    std::string fuzzdata = provider->ConsumeRandomLengthString();
    int32_t intPara = provider->ConsumeIntegral<int32_t>();
    std::string argument0 = provider->ConsumeRandomLengthString();
    char argument = argument0[0];
    std::string fileData = provider->ConsumeRandomLengthString();
    std::string numberStr = std::to_string(intPara);
    std::vector<std::string> records;
    records.push_back(fileData);
    VCardUtils::EqualsIgnoreCase(fuzzdata, fuzzdata);
    VCardUtils::Trim(fuzzdata);
    VCardUtils::ToUpper(fuzzdata);
    VCardUtils::StartWith(fuzzdata, fuzzdata);
    VCardUtils::EndWith(fuzzdata, fuzzdata);
    VCardUtils::EncodeBase64(fuzzdata);
    VCardUtils::DecodeBase64(fuzzdata);
    VCardUtils::CreateFileName();
    VCardUtils::SaveFile(fuzzdata, fuzzdata);
    VCardUtils::IsPrintableAscii(fuzzdata);
    VCardUtils::GetTypeFromImLabelId(numberStr);
    VCardUtils::GetTypeFromPhoneLabelId(numberStr);
    VCardUtils::GetImageType(fuzzdata);
    VCardUtils::IsNum(fuzzdata);
    VCardUtils::ConstructListFromValue(fuzzdata, fuzzdata);
    VCardUtils::VcardtypeToInt(fuzzdata);
    VCardUtils::FormatNumber(fuzzdata);
    VCardUtils::GetPhoneNumberFormat(intPara);
    VCardUtils::GetLabelIdFromImType(fuzzdata);
    VCardUtils::HandleTypeAndLabel(intPara, fuzzdata, fuzzdata, fuzzdata);
    VCardUtils::IsPrintableAscii(fuzzdata);
    VCardUtils::IsPrintableAscii(argument);
    VCardUtils::IsPrintableAscii(records);
    VCardUtils::IsWrapPrintableAscii(records);
    VCardUtils::TrimListToString(records);
    VCardUtils::IsAllEmpty(records);
    VCardUtils::HandleCh(argument, fuzzdata);
}

void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    std::shared_ptr<FuzzedDataProvider> provider = std::make_shared<FuzzedDataProvider>(data, size);
    DecodeVcard(provider);
    DecodeVcardData(provider);
    DecodeVcardRelation(provider);
    DecodeVcardRelationData(provider);
    ContructName(provider);
    ContructNameData(provider);
    ContructRelation(provider);
    ContructRelationData(provider);
    DecodeVcardRelationV30(provider);
    DecodeVcardRelationDataV30(provider);
    DecodeVcardRelationV40(provider);
    DecodeVcardRelationDataV40(provider);
    Import(provider);
    ImportLock(provider);
    Export(provider);
    ExportLock(provider);
    ExportToStr(provider);
    VCardUtilsTest(provider);
    return;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
