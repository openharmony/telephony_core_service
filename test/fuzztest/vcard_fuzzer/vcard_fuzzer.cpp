/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

using namespace OHOS::Telephony;
namespace OHOS {
constexpr const char *FILE_NAME = "example.vcf";

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

void DecodeVcard(const uint8_t *data, size_t size)
{
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
    int32_t errorCode;
    VCardManager::GetInstance().Decode(FILE_NAME, errorCode);
}

void DecodeVcardData(const uint8_t *data, size_t size)
{
    std::string fuzzdata(reinterpret_cast<const char *>(data), size);
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
    int32_t errorCode;
    VCardManager::GetInstance().Decode(FILE_NAME, errorCode);
}

void DecodeVcardRelation(const uint8_t *data, size_t size)
{
    std::string inputString =
        "BEGIN:VCARD\r\nVERSION:2.1\r\nX_OHOS_CUSTOM;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:relation;="
        "E6=B5=8B=E8=AF=95;=E6=B5=8B=E8=AF=95=69=64;=E6=B5=8B=E8=AF=95=6E=61=6D=65\r\nX_OHOS_CUSTOM:"
        "relation;realationName;labelId;labelName\r\nEND:VCARD\r\n";
    WriteTestData(inputString);
    int32_t errorCode;
    VCardManager::GetInstance().Decode(FILE_NAME, errorCode);
}

void DecodeVcardRelationData(const uint8_t *data, size_t size)
{
    std::string fuzzdata(reinterpret_cast<const char *>(data), size);
    std::string inputString =
        "BEGIN:VCARD\r\nVERSION:2.1\r\nX_OHOS_CUSTOM;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:relation;="
        "E6=B5=8B=E8=AF=95;=E6=B5=8B=E8=AF=95=69=64;=E6=B5=8B=E8=AF=95=6E=61=6D=65\r\nX_OHOS_CUSTOM:"
        "relation;realationName;labelId;labelName\r\nEND:VCARD\r\n" +
        fuzzdata;
    WriteTestData(inputString);
    int32_t errorCode;
    VCardManager::GetInstance().Decode(FILE_NAME, errorCode);
}

void ContructName(const uint8_t *data, size_t size)
{
    auto nameData = std::make_shared<VCardNameData>();
    nameData->displayName_ = "test";
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

void ContructNameData(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    auto nameData = std::make_shared<VCardNameData>();
    std::string displayName(reinterpret_cast<const char *>(data), size);
    nameData->displayName_ = displayName;
    std::string family(reinterpret_cast<const char *>(data), size);
    nameData->family_ = family;
    std::string given(reinterpret_cast<const char *>(data), size);
    nameData->given_ = given;
    std::string middle(reinterpret_cast<const char *>(data), size);
    nameData->middle_ = middle;
    std::string suffix(reinterpret_cast<const char *>(data), size);
    nameData->suffix_ = suffix;
    std::string prefix(reinterpret_cast<const char *>(data), size);
    nameData->prefix_ = prefix;
    std::string phoneticFamily(reinterpret_cast<const char *>(data), size);
    nameData->phoneticFamily_ = phoneticFamily;
    std::string phoneticGiven(reinterpret_cast<const char *>(data), size);
    nameData->phoneticGiven_ = phoneticGiven;
    std::string phoneticMiddle(reinterpret_cast<const char *>(data), size);
    nameData->phoneticMiddle_ = phoneticMiddle;
    auto contact = std::make_shared<VCardContact>();
    contact->names_.push_back(nameData);
    auto constructor = std::make_shared<VCardConstructor>();
    auto value = constructor->ContactVCard(contact);
}

void ContructRelation(const uint8_t *data, size_t size)
{
    auto data1 = std::make_shared<VCardRelationData>();
    data1->relationName_ = "测试";
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

void ContructRelationData(const uint8_t *data, size_t size)
{
    auto data1 = std::make_shared<VCardRelationData>();
    std::string test(reinterpret_cast<const char *>(data), size);
    data1->relationName_ = test;
    std::string testId(reinterpret_cast<const char *>(data), size);
    data1->labelId_ = testId;
    std::string testName(reinterpret_cast<const char *>(data), size);
    data1->labelName_ = testName;
    auto data2 = std::make_shared<VCardRelationData>();
    std::string realationName(reinterpret_cast<const char *>(data), size);
    data2->relationName_ = realationName;
    std::string labelId(reinterpret_cast<const char *>(data), size);
    data2->labelId_ = labelId;
    std::string labelName(reinterpret_cast<const char *>(data), size);
    data2->labelName_ = labelName;
    auto contact = std::make_shared<VCardContact>();
    contact->relations_.push_back(data1);
    contact->relations_.push_back(data2);
    auto constructor = std::make_shared<VCardConstructor>();
    auto value = constructor->ContactVCard(contact);
}

void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    DecodeVcard(data, size);
    DecodeVcardData(data, size);
    DecodeVcardRelation(data, size);
    DecodeVcardRelationData(data, size);
    ContructName(data, size);
    ContructNameData(data, size);
    ContructRelation(data, size);
    ContructRelationData(data, size);
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
