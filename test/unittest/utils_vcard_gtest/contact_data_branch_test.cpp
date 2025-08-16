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
    EXPECT_EQ((contact->phones_).size(), 1);

    contact->AddPhonesData("", "", values, parasMap);
    EXPECT_EQ((contact->phones_).size(), 2);

    std::map<std::string, std::vector<std::string>> parasMapPhones = {{"TYPE", {"VOICE"}}};
    contact->AddPhonesData("1966159148", "", values, parasMapPhones);
    EXPECT_EQ((contact->phones_).size(), 3);
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

HWTEST_F(ContactDataBranchTest, Telephony_VCardContact_006, Function | MediumTest | Level3)
{
    std::shared_ptr<VCardContact> contact = std::make_shared<VCardContact>();
    std::map<std::string, std::vector<std::string>> parasMap;

    contact->AddImppDatas("sip:", parasMap);
    std::string value = "1";
    contact->ConvertHarmonyEvents(VCARD_TYPE_X_MOBILE_EVENTS, value);
    value = "2";
    contact->ConvertHarmonyEvents(VCARD_TYPE_X_MOBILE_EVENTS, value);
    value = "4";
    contact->ConvertHarmonyEvents(VCARD_TYPE_X_MOBILE_EVENTS, value);
    EXPECT_EQ((contact->sips_).size(), 0);
}

HWTEST_F(ContactDataBranchTest, Importtest, Function | MediumTest | Level3)
{
    VCardManager manager;
    int32_t accountId = 123;
    int32_t errorCode = 0;
    std::string invalidPath = "path/to/invalid.vcf";
    EXPECT_NE(manager.Import(invalidPath, accountId), TELEPHONY_SUCCESS);

    accountId = -1;
    EXPECT_NE(manager.Import(invalidPath, accountId), TELEPHONY_SUCCESS);

    errorCode = 0;
    std::string emptyPath = "";
    EXPECT_NE(manager.Import(invalidPath, accountId), TELEPHONY_SUCCESS);
}

HWTEST_F(ContactDataBranchTest, Decodetest, Function | MediumTest | Level3)
{
    VCardManager manager;
    int32_t errorCode = TELEPHONY_SUCCESS;
    std::string invalidPath = "nonexistent_file.vcf";
    manager.Decode(invalidPath, errorCode);
    EXPECT_NE(errorCode, TELEPHONY_SUCCESS);
}

HWTEST_F(ContactDataBranchTest, BatchInsertContactDbAbilityrest_001, Function | MediumTest | Level3)
{
    VCardManager manager;
    int32_t errorCode = 0;
    manager.BatchInsertContactDbAbility(1, errorCode);
    EXPECT_NE(errorCode, TELEPHONY_ERR_LOCAL_PTR_NULL);

    std::shared_ptr<VCardManager::DecodeListener> listener = std::make_shared<VCardManager::DecodeListener>();
    listener->contacts_.push_back(std::make_shared<VCardContact>());
    manager.listener_ = listener;
    manager.BatchInsertContactDbAbility(1, errorCode);
    EXPECT_EQ(errorCode, TELEPHONY_ERR_LOCAL_PTR_NULL);

    int32_t accountId = 123;
    EXPECT_NE(manager.listener_->GetContacts().size(), 0);
    manager.BatchInsertContactDbAbility(accountId, errorCode);
    EXPECT_NE(errorCode, TELEPHONY_ERR_VCARD_FILE_INVALID);

    const int BATCH_SIZE = 10;
    for (int i = 0; i < BATCH_SIZE * 2; ++i) {
        std::shared_ptr<VCardContact> contact = std::make_shared<VCardContact>();
        manager.listener_->GetContacts();
    }
    EXPECT_GE(manager.listener_->GetContacts().size(), BATCH_SIZE);
    manager.BatchInsertContactDbAbility(accountId, errorCode);
    
    EXPECT_NE(errorCode, TELEPHONY_SUCCESS);
}

HWTEST_F(ContactDataBranchTest, InsertContactDbAbilityrest_001, Function | MediumTest | Level3)
{
    VCardManager manager;
    int32_t errorCode = 0;
    manager.InsertContactDbAbility(1,errorCode);
    EXPECT_NE(errorCode, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(ContactDataBranchTest, BatchInsertContactDatatest_001, Function | MediumTest | Level3)
{
    VCardManager manager;
    int32_t errorCode = 0;
    vector<int32_t> rawIds = {1, 2};
    vector<std::shared_ptr<VCardContact>> contactList;
    contactList.push_back(std::make_shared<VCardContact>());
    contactList.push_back(std::make_shared<VCardContact>());
    manager.BatchInsertContactData(rawIds, contactList, errorCode);
    EXPECT_NE(errorCode, 0);
}

HWTEST_F(ContactDataBranchTest, BatchInsertContactDatatest_002, Function | MediumTest | Level3)
{
    VCardManager manager;
    int32_t errorCode = 0;
    vector<int32_t> rawIds = {1};
    vector<std::shared_ptr<VCardContact>> contactList;
    contactList.push_back(nullptr);
    manager.BatchInsertContactData(rawIds, contactList, errorCode);
    EXPECT_NE(errorCode, 0);
}

HWTEST_F(ContactDataBranchTest, BatchInsertContactDatatest_003, Function | MediumTest | Level3)
{
    VCardManager manager;
    int32_t errorCode = 0;
    vector<int32_t> rawIds;
    vector<std::shared_ptr<VCardContact>> contactList;
    manager.BatchInsertContactData(rawIds, contactList, errorCode);
    EXPECT_NE(errorCode, 0);
}

HWTEST_F(ContactDataBranchTest, SplitContactsVectortest_001, Function | MediumTest | Level3)
{
    VCardManager manager;
    vector<std::shared_ptr<VCardContact>> contacts;
    for (int i = 0; i < 6; ++i) {
        contacts.push_back(std::make_shared<VCardContact>());
    }
    size_t step = 2;
    auto result = manager.SplitContactsVector(contacts, step);
    EXPECT_EQ(result.size(), 3);
    for (const auto& vec : result) {
        EXPECT_EQ(vec.size(), 2);
    }
}

HWTEST_F(ContactDataBranchTest, SplitContactsVectortest_003, Function | MediumTest | Level3)
{
    VCardManager manager;
    vector<std::shared_ptr<VCardContact>> contacts;
    size_t step = 2;
    auto result = manager.SplitContactsVector(contacts, step);
    EXPECT_NE(result.size(), 0);

    contacts.push_back(std::make_shared<VCardContact>());
    step = 5;
    result = manager.SplitContactsVector(contacts, step);
    EXPECT_EQ(result.size(), 1);
    EXPECT_NE(result[0].size(), 3);

    contacts.push_back(std::make_shared<VCardContact>());
    step = 4;
    result = manager.SplitContactsVector(contacts, step);
    EXPECT_EQ(result.size(), 1);
    EXPECT_NE(result[0].size(), 4);


    contacts.push_back(std::make_shared<VCardContact>());
    step = 1;
    result = manager.SplitContactsVector(contacts, step);
    EXPECT_NE(result.size(), 5);
    for (const auto& vec : result) {
        EXPECT_EQ(vec.size(), 1);
    }
}

HWTEST_F(ContactDataBranchTest, IsContactsIdExittest_001, Function | MediumTest | Level3)
{
    VCardManager manager;
    int32_t accountId = 123;

    auto result = manager.IsContactsIdExit(accountId);
    EXPECT_FALSE(result);
}

HWTEST_F(ContactDataBranchTest, ParameterTypeAndCharsetChecktest_001, Function | MediumTest | Level3)
{
    VCardManager manager;
    int32_t cardType = VERSION_21_NUM + 1;
    string charset = "";
    int32_t errorCode = 0;

    bool result = manager.ParameterTypeAndCharsetCheck(cardType, charset, errorCode);
    EXPECT_TRUE(result);
    EXPECT_EQ(errorCode, TELEPHONY_SUCCESS);

    charset = DEFAULT_CHARSET;
    result = manager.ParameterTypeAndCharsetCheck(cardType, charset, errorCode);
    EXPECT_TRUE(result);
    EXPECT_EQ(errorCode, TELEPHONY_SUCCESS);

    cardType = VERSION_21_NUM - 1;
    charset = "";
    result = manager.ParameterTypeAndCharsetCheck(cardType, charset, errorCode);
    EXPECT_FALSE(result);
    EXPECT_EQ(errorCode, TELEPHONY_ERR_ARGUMENT_INVALID);

    cardType = VERSION_40_NUM + 1;
    charset = "";
    result = manager.ParameterTypeAndCharsetCheck(cardType, charset, errorCode);
    EXPECT_FALSE(result);
    EXPECT_EQ(errorCode, TELEPHONY_ERR_ARGUMENT_INVALID);

    cardType = VERSION_21_NUM + 1;
    charset = "";
    result = manager.ParameterTypeAndCharsetCheck(cardType, charset, errorCode);
    EXPECT_TRUE(result);
    EXPECT_NE(errorCode, TELEPHONY_ERR_ARGUMENT_INVALID);

    cardType = VERSION_21_NUM;
    charset = "";
    result = manager.ParameterTypeAndCharsetCheck(cardType, charset, errorCode);
    EXPECT_TRUE(result);
    EXPECT_NE(errorCode, TELEPHONY_ERR_ARGUMENT_INVALID);

    cardType = VERSION_40_NUM;
    charset = "";
    result = manager.ParameterTypeAndCharsetCheck(cardType, charset, errorCode);
    EXPECT_TRUE(result);
    EXPECT_NE(errorCode, TELEPHONY_ERR_ARGUMENT_INVALID);

    cardType = VERSION_21_NUM + 1;
    charset = "UTF-8";
    result = manager.ParameterTypeAndCharsetCheck(cardType, charset, errorCode);
    EXPECT_TRUE(result);
    EXPECT_NE(errorCode, TELEPHONY_ERR_ARGUMENT_INVALID);
}

HWTEST_F(ContactDataBranchTest, Exporttest_001, Function | MediumTest | Level3)
{
    VCardManager manager;
    string path = "";
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(RawContact::ACCOUNT_ID, "1");
    int32_t cardType = VERSION_21_NUM + 1;
    string charset = DEFAULT_CHARSET;

    int32_t result = manager.Export(path, predicates, cardType, charset);

    EXPECT_NE(result, TELEPHONY_SUCCESS);
    EXPECT_TRUE(path.empty());

    cardType = VERSION_21_NUM - 1;
    charset = DEFAULT_CHARSET;
    result = manager.Export(path, predicates, cardType, charset);
    EXPECT_NE(result, TELEPHONY_SUCCESS);
    EXPECT_EQ(result, TELEPHONY_ERR_ARGUMENT_INVALID);

    path = "";
    predicates.EqualTo(RawContact::ACCOUNT_ID, "999");
    cardType = VERSION_21_NUM + 1;
    charset = DEFAULT_CHARSET;

    manager.VCardManager::Export(path, predicates, cardType, charset);

    EXPECT_NE(result, TELEPHONY_SUCCESS);
    EXPECT_NE(result, TELEPHONY_ERR_LOCAL_PTR_NULL);

    path = "";
    predicates.EqualTo(RawContact::ACCOUNT_ID, "1");
    cardType = VERSION_21_NUM + 1;
    charset = "invalid_charset";

    result = manager.Export(path, predicates, cardType, charset);

    EXPECT_NE(result, TELEPHONY_SUCCESS);
    EXPECT_EQ(result, TELEPHONY_ERR_ARGUMENT_INVALID);

    path = "";
    predicates.EqualTo(RawContact::ACCOUNT_ID, "1");
    cardType = VERSION_21_NUM + 1;
    charset = DEFAULT_CHARSET;

    result = manager.Export(path, predicates, cardType, charset);

    EXPECT_NE(result, TELEPHONY_SUCCESS);
    EXPECT_NE(result, TELEPHONY_ERROR);

    path = "";
    predicates.EqualTo(RawContact::ACCOUNT_ID, "1");
    cardType = VERSION_21_NUM + 1;
    charset = DEFAULT_CHARSET;

    result = manager.Export(path, predicates, cardType, charset);

    EXPECT_NE(result, TELEPHONY_SUCCESS);
    EXPECT_TRUE(path.empty());
    EXPECT_FALSE(path.find(VCARD_EXPORT_FILE_PATH) != string::npos);

    path = "/tmp/test_";
    predicates.EqualTo(RawContact::ACCOUNT_ID, "1");
    cardType = VERSION_21_NUM + 1;
    charset = DEFAULT_CHARSET;

    result = manager.Export(path, predicates, cardType, charset);

    EXPECT_NE(result, TELEPHONY_SUCCESS);
    EXPECT_FALSE(path.empty());
    EXPECT_TRUE(path.find("/tmp/test_") != string::npos);
}
} // namespace Telephony
} // namespace OHOS
