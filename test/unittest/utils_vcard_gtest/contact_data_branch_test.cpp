/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#define private public
#define protected public

#include "vcard_contact.h"
#include "vcard_manager.h"
#include "telephony_errors.h"
#include <fcntl.h>
#include <iostream>
#include <gtest/gtest.h>

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

namespace {
constexpr int32_t MAX_VALUE_SIZE = 5;
constexpr const char *TEST_VERSION_21 = "2.1";
constexpr const char *TEST_VERSION_30 = "3.0";
constexpr const char *TEST_VERSION_40 = "4.0";
const std::string TEST_VCARD_PARAM_SORT_AS = "SORT-AS";
const std::string TEST_VCARD_PARAM_TYPE = "TYPE";
constexpr const int32_t MIN_INVALID_VERSION = -1;
constexpr const int32_t TEST_VERSION_21_NUM = 0;
constexpr const int32_t MAX_INVALID_VERSION = 3;
} // namespace

class ContactDataBranchTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ContactDataBranchTest::SetUpTestCase() {}

void ContactDataBranchTest::TearDownTestCase() {}

void ContactDataBranchTest::SetUp() {}

void ContactDataBranchTest::TearDown() {}

HWTEST_F(ContactDataBranchTest, Telephony_VCardContact_001, Function | MediumTest | Level3)
{
    std::shared_ptr<VCardContact> contact = std::make_shared<VCardContact>();
    std::vector<DataShare::DataShareValuesBucket> contactDataValues;
    contact->BuildValuesBucket(1, contactDataValues, nullptr);
    EXPECT_EQ(contactDataValues.size(), 0);

    EXPECT_EQ(contact->BuildOneData(nullptr), TELEPHONY_ERROR);
    EXPECT_EQ(contact->BuildOtherData(0, nullptr), TELEPHONY_SUCCESS);

    std::vector<std::string> values;
    std::map<std::string, std::vector<std::string>> parasMap;
    contact->nameData_ = nullptr;
    contact->HandleName(values, parasMap);

    contact->nameData_ = std::make_shared<VCardNameData>();
    ASSERT_NE(contact->nameData_, nullptr);
    contact->HandleName(values, parasMap);

    values.push_back("testValue1");
    values.push_back("testValue2");
    values.push_back("testValue3");
    ASSERT_NE(values.size(), 0);
    contact->HandleName(values, parasMap);

    values.push_back("testValue4");
    values.push_back("testValue5");
    values.push_back("testValue6");
    ASSERT_GT(values.size(), MAX_VALUE_SIZE);
    contact->HandleName(values, parasMap);
}

HWTEST_F(ContactDataBranchTest, Telephony_VCardContact_002, Function | MediumTest | Level3)
{
    std::shared_ptr<VCardContact> contact = std::make_shared<VCardContact>();

    contact->nameData_ = nullptr;
    std::map<std::string, std::vector<std::string>> parasMap;
    std::vector<std::string> elems;
    contact->HandleSortAsName(parasMap);
    contact->HandlePhoneticNameFromSound(elems);

    contact->nameData_ = std::make_shared<VCardNameData>();
    ASSERT_NE(contact->nameData_, nullptr);

    std::string testStr = "";
    contact->nameData_->SetPhoneticFamily(testStr);
    contact->nameData_->SetPhoneticMiddle(testStr);
    contact->nameData_->SetPhoneticGiven(testStr);
    contact->HandlePhoneticNameFromSound(elems);
    EXPECT_TRUE(contact->nameData_->GetPhoneticFamily().empty());

    contact->vCardType_ = TEST_VERSION_30;
    testStr = "testStr";
    contact->nameData_->SetPhoneticFamily(testStr);
    contact->nameData_->SetPhoneticMiddle(testStr);
    contact->nameData_->SetPhoneticGiven(testStr);
    ASSERT_FALSE(contact->nameData_->GetPhoneticFamily().empty());
    contact->HandleSortAsName(parasMap);
    contact->HandlePhoneticNameFromSound(elems);

    elems.push_back("");
    contact->HandlePhoneticNameFromSound(elems);
    EXPECT_TRUE(contact->nameData_->GetPhoneticFamily().empty());

    elems.push_back("testGiven");
    contact->HandlePhoneticNameFromSound(elems);
    EXPECT_STREQ((contact->nameData_->GetPhoneticGiven()).c_str(), "testGiven");

    elems.push_back("testMiddle");
    contact->HandlePhoneticNameFromSound(elems);
    EXPECT_STREQ((contact->nameData_->GetPhoneticMiddle()).c_str(), "testMiddle");
}

HWTEST_F(ContactDataBranchTest, Telephony_VCardContact_003, Function | MediumTest | Level3)
{
    std::shared_ptr<VCardContact> contact = std::make_shared<VCardContact>();

    std::map<std::string, std::vector<std::string>> paramMap;
    EXPECT_STREQ((contact->BuildSinglePhoneticNameFromSortAsParam(paramMap)).c_str(), "");

    paramMap[TEST_VCARD_PARAM_SORT_AS] = {};
    ASSERT_EQ(paramMap.size(), 1);
    EXPECT_STREQ((contact->BuildSinglePhoneticNameFromSortAsParam(paramMap)).c_str(), "");

    paramMap[TEST_VCARD_PARAM_SORT_AS] = {"testValue"};
    contact->vCardType_ = TEST_VERSION_21;
    ASSERT_EQ(paramMap.size(), 1);
    EXPECT_STREQ((contact->BuildSinglePhoneticNameFromSortAsParam(paramMap)).c_str(), "testValue");

    std::string testStr = "";
    contact->organizations_.clear();
    contact->HandleTitleValue(testStr);

    std::vector<std::string> typeCollection;
    contact->HandleSipCase(testStr, typeCollection);
    EXPECT_EQ((contact->sips_).size(), 0);

    testStr = "sip:";
    contact->HandleSipCase(testStr, typeCollection);
    EXPECT_EQ((contact->sips_).size(), 0);
}

HWTEST_F(ContactDataBranchTest, Telephony_VCardContact_004, Function | MediumTest | Level3)
{
    std::shared_ptr<VCardContact> contact = std::make_shared<VCardContact>();
    std::vector<std::string> values;
    std::map<std::string, std::vector<std::string>> parasMap;
    contact->nameData_ = nullptr;

    contact->AddNameData("", "", values, parasMap, "");

    contact->nameData_ = std::make_shared<VCardNameData>();
    ASSERT_NE(contact->nameData_, nullptr);
    contact->AddNameData("testName", "", values, parasMap, "");
    EXPECT_TRUE(contact->nameData_->GetPhoneticFamily().empty());

    parasMap[TEST_VCARD_PARAM_TYPE] = {"testValue"};
    contact->SetSip("", parasMap, "");
    EXPECT_EQ((contact->sips_).size(), 0);

    contact->vCardType_ = TEST_VERSION_40;
    contact->AddPhonesData("", "sip:", values, parasMap);
    EXPECT_EQ((contact->sips_).size(), 0);

    parasMap.clear();
    ASSERT_TRUE(parasMap.empty());
    contact->AddPhonesData("", "tel:", values, parasMap);
    EXPECT_EQ((contact->phones_).size(), 0);

    contact->AddPhonesData("", "", values, parasMap);
    EXPECT_EQ((contact->phones_).size(), 0);
}

HWTEST_F(ContactDataBranchTest, Telephony_VCardContact_005, Function | MediumTest | Level3)
{
    std::shared_ptr<VCardContact> contact = std::make_shared<VCardContact>();
    std::map<std::string, std::vector<std::string>> parasMap;

    contact->AddImppDatas("sip:", parasMap);
    EXPECT_EQ((contact->sips_).size(), 0);

    parasMap[TEST_VCARD_PARAM_TYPE] = {"testValue"};
    contact->AddImppDatas("sip:", parasMap);
    EXPECT_EQ((contact->sips_).size(), 0);
}

HWTEST_F(ContactDataBranchTest, Telephony_VCardManager, Function | MediumTest | Level3)
{
    VCardManager& vCardManager= VCardManager::GetInstance();
    vCardManager.listener_ = nullptr;

    int32_t errorCode = 0;
    vCardManager.InsertContactDbAbility(0, errorCode);
    EXPECT_EQ(errorCode, TELEPHONY_ERR_LOCAL_PTR_NULL);

    errorCode = 0;
    vCardManager.BatchInsertContactDbAbility(0, errorCode);
    EXPECT_EQ(errorCode, TELEPHONY_ERR_LOCAL_PTR_NULL);

    errorCode = 0;
    EXPECT_EQ(vCardManager.InsertContactData(0, nullptr), TELEPHONY_ERROR);
    EXPECT_FALSE(vCardManager.ParameterTypeAndCharsetCheck(MIN_INVALID_VERSION, "", errorCode));
    EXPECT_EQ(errorCode, TELEPHONY_ERR_ARGUMENT_INVALID);

    errorCode = 0;
    EXPECT_FALSE(vCardManager.ParameterTypeAndCharsetCheck(MAX_INVALID_VERSION, "", errorCode));
    EXPECT_EQ(errorCode, TELEPHONY_ERR_ARGUMENT_INVALID);

    errorCode = 0;
    EXPECT_FALSE(vCardManager.ParameterTypeAndCharsetCheck(TEST_VERSION_21_NUM, "testCharset", errorCode));
    EXPECT_EQ(errorCode, TELEPHONY_ERR_ARGUMENT_INVALID);

    std::string testStr = "";
    DataShare::DataSharePredicates predicates;
    EXPECT_EQ(vCardManager.ExportLock(testStr, nullptr, predicates, 0, testStr), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(vCardManager.Export(testStr, predicates, MIN_INVALID_VERSION, testStr), TELEPHONY_ERR_ARGUMENT_INVALID);
}
} // namespace Telephony
} // namespace OHOS
