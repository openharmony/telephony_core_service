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
#include "vcard_email_data.h"
#include "vcard_event_data.h"
#include "vcard_group_data.h"
#include "vcard_im_data.h"
#include "vcard_manager.h"
#include "vcard_name_data.h"
#include "vcard_nickname_data.h"
#include "vcard_note_data.h"
#include "vcard_organization_data.h"
#include "vcard_phone_data.h"
#include "vcard_photo_data.h"
#include "vcard_postal_data.h"
#include "vcard_relation_data.h"
#include "vcard_configuration.h"
#include "vcard_contact.h"
#include "vcard_constant.h"
#include "vcard_decoder_v21.h"
#include "vcard_decoder_v30.h"
#include "vcard_decoder_v40.h"
#include "vcard_encoder.h"
#include "vcard_utils.h"
#include "telephony_errors.h"

#include <fcntl.h>
#include <iostream>
#include <gtest/gtest.h>

using namespace testing::ext;

namespace OHOS {
namespace Telephony {
#ifndef TEL_TEST_UNSUPPORT

class ContactDataTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void SetNameData(const std::string &family, const std::string &given, const std::string &middle,
        const std::string &prefix, const std::string &suffix);
    void SetNameData(const std::string &family, const std::string &given, const std::string &middle,
        const std::string &displayName);
    void SetNameDataInfo(const std::string &phoneticFamily, const std::string &phoneticGiven,
        const std::string &phoneticMiddle);
};

void ContactDataTest::SetUpTestCase() {}

void ContactDataTest::TearDownTestCase() {}

void ContactDataTest::SetUp() {}

void ContactDataTest::TearDown() {}

std::shared_ptr<VCardNameData> nameData_ = std::make_shared<VCardNameData>();
std::shared_ptr<VCardContact> contact_ = std::make_shared<VCardContact>();

void ContactDataTest::SetNameData(const std::string &family, const std::string &given, const std::string &middle,
    const std::string &prefix, const std::string &suffix)
{
    nameData_->SetFamily(family);
    nameData_->SetGiven(given);
    nameData_->SetMiddle(middle);
    nameData_->SetPrefix(prefix);
    nameData_->SetSuffix(suffix);
}

void ContactDataTest::SetNameData(const std::string &family, const std::string &given, const std::string &middle,
    const std::string &displayName)
{
    nameData_->SetFamily(family);
    nameData_->SetGiven(given);
    nameData_->SetMiddle(middle);
    nameData_->SetPrefix(displayName);
}

void ContactDataTest::SetNameDataInfo(const std::string &phoneticFamily, const std::string &phoneticGiven,
    const std::string &phoneticMiddle)
{
    nameData_->SetPhoneticFamily(phoneticFamily);
    nameData_->SetPhoneticGiven(phoneticGiven);
    nameData_->SetPhoneticMiddle(phoneticMiddle);
}

HWTEST_F(ContactDataTest, VCardEmailData_BuildData, Function | MediumTest | Level3)
{
    std::shared_ptr<DataShare::DataShareResultSet> resultSet = std::make_shared<DataShare::DataShareResultSet>();
    VCardEmailData emailData;
    EXPECT_EQ(emailData.BuildData(resultSet), TELEPHONY_SUCCESS);

    EXPECT_EQ(emailData.BuildData(nullptr), TELEPHONY_ERROR);
}

HWTEST_F(ContactDataTest, VCardEventData_BuildData, Function | MediumTest | Level3)
{
    std::shared_ptr<DataShare::DataShareResultSet> resultSet = std::make_shared<DataShare::DataShareResultSet>();
    VCardEventData eventData;
    EXPECT_EQ(eventData.BuildData(resultSet), TELEPHONY_SUCCESS);
    EXPECT_EQ(eventData.BuildData(nullptr), TELEPHONY_ERROR);
}

HWTEST_F(ContactDataTest, VCardImData_BuildData, Function | MediumTest | Level3)
{
    std::shared_ptr<DataShare::DataShareResultSet> resultSet = std::make_shared<DataShare::DataShareResultSet>();
    VCardImData imData;
    EXPECT_EQ(imData.BuildData(resultSet), TELEPHONY_SUCCESS);
    EXPECT_EQ(imData.BuildData(nullptr), TELEPHONY_ERROR);
}

HWTEST_F(ContactDataTest, VCardNameData_BuildValuesBucket, Function | MediumTest | Level3)
{
    DataShare::DataShareValuesBucket valuesBucket;
    std::string family = "";
    std::string given = "";
    std::string middle = "";
    std::string prefix = "";
    std::string suffix = "";
    std::string phoneticGiven = "";
    std::string phoneticFamily = "";
    std::string phoneticMiddle = "";
    SetNameData(family, given, middle, prefix, suffix);
    SetNameDataInfo(phoneticGiven, phoneticFamily, phoneticMiddle);
    EXPECT_EQ(nameData_->BuildValuesBucket(valuesBucket), TELEPHONY_SUCCESS);
    family = "family";
    given = "given";
    middle = "middle";
    prefix = "prefix";
    suffix = "suffix";
    phoneticGiven = "phoneticGiven";
    phoneticFamily = "phoneticFamily";
    phoneticMiddle = "phoneticMiddle";
    SetNameData(family, given, middle, prefix, suffix);
    SetNameDataInfo(phoneticGiven, phoneticFamily, phoneticMiddle);

    EXPECT_EQ(nameData_->BuildValuesBucket(valuesBucket), TELEPHONY_SUCCESS);
}

HWTEST_F(ContactDataTest, VCardNameData_BuildData, Function | MediumTest | Level3)
{
    std::shared_ptr<DataShare::DataShareResultSet> resultSet = std::make_shared<DataShare::DataShareResultSet>();
    VCardNameData nameData;
    EXPECT_EQ(nameData.BuildData(resultSet), TELEPHONY_SUCCESS);
    EXPECT_EQ(nameData.BuildData(nullptr), TELEPHONY_ERROR);
}

HWTEST_F(ContactDataTest, VCardNicknameData_BuildData, Function | MediumTest | Level3)
{
    std::shared_ptr<DataShare::DataShareResultSet> resultSet = std::make_shared<DataShare::DataShareResultSet>();
    VCardNicknameData nickNameData;
    EXPECT_EQ(nickNameData.BuildData(resultSet), TELEPHONY_SUCCESS);
    EXPECT_EQ(nickNameData.BuildData(nullptr), TELEPHONY_ERROR);
}

HWTEST_F(ContactDataTest, VCardNoteData_BuildData, Function | MediumTest | Level3)
{
    std::shared_ptr<DataShare::DataShareResultSet> resultSet = std::make_shared<DataShare::DataShareResultSet>();
    VCardNoteData noteData;
    EXPECT_EQ(noteData.BuildData(resultSet), TELEPHONY_SUCCESS);
    EXPECT_EQ(noteData.BuildData(nullptr), TELEPHONY_ERROR);
}

HWTEST_F(ContactDataTest, VCardOrganizationData_BuildValuesBucket, Function | MediumTest | Level3)
{
    VCardOrganizationData organizationData;
    DataShare::DataShareValuesBucket valuesBucket;
    std::string organization = "";
    std::string departmentName = "";
    std::string company = "";
    std::string title = "";
    std::string phoneticName = "";
    int32_t type = 0;
    organizationData.InitOrganizationData(organization, departmentName, company, phoneticName, title, type);
    EXPECT_EQ(organizationData.BuildValuesBucket(valuesBucket), TELEPHONY_SUCCESS);
    company = "company";
    title = "title";
    organizationData.InitOrganizationData(organization, departmentName, company, phoneticName, title, type);
    EXPECT_EQ(organizationData.BuildValuesBucket(valuesBucket), TELEPHONY_SUCCESS);
}

HWTEST_F(ContactDataTest, VCardOrganizationData_BuildData, Function | MediumTest | Level3)
{
    std::shared_ptr<DataShare::DataShareResultSet> resultSet = std::make_shared<DataShare::DataShareResultSet>();
    VCardOrganizationData organizationData;
    EXPECT_EQ(organizationData.BuildData(resultSet), TELEPHONY_SUCCESS);
    EXPECT_EQ(organizationData.BuildData(nullptr), TELEPHONY_ERROR);
}

HWTEST_F(ContactDataTest, VCardPhoneData_BuildData, Function | MediumTest | Level3)
{
    std::shared_ptr<DataShare::DataShareResultSet> resultSet = std::make_shared<DataShare::DataShareResultSet>();
    VCardPhoneData phoneData;
    EXPECT_EQ(phoneData.BuildData(resultSet), TELEPHONY_SUCCESS);
    EXPECT_EQ(phoneData.BuildData(nullptr), TELEPHONY_ERROR);
}

HWTEST_F(ContactDataTest, VCardPhotoData_BuildData, Function | MediumTest | Level3)
{
    std::shared_ptr<DataShare::DataShareResultSet> resultSet = std::make_shared<DataShare::DataShareResultSet>();
    VCardPhotoData photoData;
    EXPECT_EQ(photoData.BuildData(resultSet), TELEPHONY_SUCCESS);
    EXPECT_EQ(photoData.BuildData(nullptr), TELEPHONY_ERROR);
}

HWTEST_F(ContactDataTest, VCardContact_AddRawData, Function | MediumTest | Level3)
{
    std::shared_ptr<VCardRawData> rawData = std::make_shared<VCardRawData>();
    int32_t errorCode = 0;
    contact_->AddRawData(nullptr, errorCode);
    rawData->SetName("Name");
    rawData->SetRawValue("RawValue");
    rawData->SetByte("");
    rawData->SetValues({});
    rawData->AppendGroup({});
    contact_->AddRawData(rawData, errorCode);
    EXPECT_EQ((rawData->GetValue()).size(), 0);
    EXPECT_TRUE((rawData->GetByte()).empty());

    rawData->SetValues({"Value1", "Value2"});
    contact_->AddRawData(rawData, errorCode);
    EXPECT_NE((rawData->GetValue()).size(), 0);
    EXPECT_TRUE((rawData->GetByte()).empty());

    rawData->SetByte("Byte");
    contact_->AddRawData(rawData, errorCode);
    EXPECT_NE((rawData->GetValue()).size(), 0);
    EXPECT_FALSE((rawData->GetByte()).empty());

    rawData->SetValues({});
    rawData->SetByte("Byte");
    contact_->AddRawData(rawData, errorCode);
    EXPECT_EQ((rawData->GetValue()).size(), 0);
    EXPECT_FALSE((rawData->GetByte()).empty());
}

HWTEST_F(ContactDataTest, VCardContact_AddDatas001, Function | MediumTest | Level3)
{
    std::shared_ptr<VCardRawData> rawData = std::make_shared<VCardRawData>();
    int32_t errorCode = 0;
    rawData->SetName("Name");
    rawData->SetRawValue("RawValue");
    rawData->SetByte("Byte");
    rawData->SetValues({"Value1", "Value2"});
    rawData->AppendGroup({"Group"});
    contact_->AddRawData(rawData, errorCode);
    EXPECT_NE((rawData->GetValue()).size(), 0);
    EXPECT_FALSE((rawData->GetByte()).empty());

    rawData->SetName(VCARD_TYPE_VERSION);
    contact_->AddRawData(rawData, errorCode);
    rawData->SetName(VCARD_TYPE_FN);
    contact_->AddRawData(rawData, errorCode);
    rawData->SetName(VCARD_TYPE_NAME);
    contact_->AddRawData(rawData, errorCode);
    rawData->SetName(VCARD_TYPE_N);
    contact_->AddRawData(rawData, errorCode);
    rawData->SetName(VCARD_TYPE_SORT_STRING);
    contact_->AddRawData(rawData, errorCode);
    rawData->SetName(VCARD_TYPE_X_PHONETIC_FIRST_NAME);
    contact_->AddRawData(rawData, errorCode);
    rawData->SetName(VCARD_TYPE_X_PHONETIC_LAST_NAME);
    contact_->AddRawData(rawData, errorCode);
    rawData->SetName(VCARD_TYPE_X_PHONETIC_MIDDLE_NAME);
    contact_->AddRawData(rawData, errorCode);

    EXPECT_NE((rawData->GetValue()).size(), 0);
    EXPECT_FALSE((rawData->GetByte()).empty());
}

HWTEST_F(ContactDataTest, VCardContact_AddDatas002, Function | MediumTest | Level3)
{
    std::shared_ptr<VCardRawData> rawData = std::make_shared<VCardRawData>();
    int32_t errorCode = 0;
    rawData->SetName(VCARD_TYPE_NICKNAME);
    rawData->SetRawValue("RawValue");
    rawData->SetByte("Byte");
    rawData->SetValues({"Value1", "Value2"});
    rawData->AppendGroup({"Group"});
    contact_->AddRawData(rawData, errorCode);
    EXPECT_NE((rawData->GetValue()).size(), 0);
    EXPECT_FALSE((rawData->GetByte()).empty());

    rawData->SetName(VCARD_TYPE_SOUND);
    contact_->AddRawData(rawData, errorCode);
    rawData->SetName(VCARD_TYPE_ADR);
    contact_->AddRawData(rawData, errorCode);
    rawData->SetName(VCARD_TYPE_EMAIL);
    contact_->AddRawData(rawData, errorCode);
    rawData->SetName(VCARD_TYPE_ORG);
    contact_->AddRawData(rawData, errorCode);
    rawData->SetName(VCARD_TYPE_TITLE);
    contact_->AddRawData(rawData, errorCode);
    rawData->SetName(VCARD_TYPE_PHOTO);
    contact_->AddRawData(rawData, errorCode);
    rawData->SetName(VCARD_TYPE_LOGO);
    contact_->AddRawData(rawData, errorCode);
    rawData->SetName(VCARD_TYPE_TEL);
    contact_->AddRawData(rawData, errorCode);

    EXPECT_NE((rawData->GetValue()).size(), 0);
    EXPECT_FALSE((rawData->GetByte()).empty());
}

HWTEST_F(ContactDataTest, VCardContact_AddOtherDatas001, Function | MediumTest | Level3)
{
    std::shared_ptr<VCardRawData> rawData = std::make_shared<VCardRawData>();
    int32_t errorCode = 0;
    rawData->SetName(VCARD_TYPE_X_SKYPE_PSTNNUMBER);
    rawData->SetRawValue("RawValue");
    rawData->SetByte("Byte");
    rawData->SetValues({"Value1", "Value2"});
    rawData->AppendGroup({"Group"});
    contact_->AddRawData(rawData, errorCode);
    EXPECT_NE((rawData->GetValue()).size(), 0);
    EXPECT_FALSE((rawData->GetByte()).empty());

    rawData->SetName(VCARD_TYPE_NOTE);
    contact_->AddRawData(rawData, errorCode);
    rawData->SetName(VCARD_TYPE_URL);
    contact_->AddRawData(rawData, errorCode);
    rawData->SetName(VCARD_TYPE_BDAY);
    contact_->AddRawData(rawData, errorCode);

    std::vector<DataShare::DataShareValuesBucket> contactDataValues;
    rawData->SetValues({"2000-1-1"});
    contact_->AddRawData(rawData, errorCode);
    int32_t result = contact_->BuildContactData(1, contactDataValues);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);

    rawData->SetName(VCARD_TYPE_ANNIVERSARY);
    contact_->AddRawData(rawData, errorCode);

    rawData->SetName(VCARD_TYPE_IMPP);
    contact_->AddRawData(rawData, errorCode);
    rawData->SetName(VCARD_TYPE_X_SIP);
    contact_->AddRawData(rawData, errorCode);
    rawData->SetName(VCARD_TYPE_X_OHOS_CUSTOM);
    contact_->AddRawData(rawData, errorCode);

    EXPECT_NE((rawData->GetValue()).size(), 0);
    EXPECT_FALSE((rawData->GetByte()).empty());
}

HWTEST_F(ContactDataTest, VCardContact_AddOtherDatas002, Function | MediumTest | Level3)
{
    std::shared_ptr<VCardRawData> rawData = std::make_shared<VCardRawData>();
    int32_t errorCode = 0;
    rawData->SetName(VCARD_TYPE_X_AIM);
    rawData->SetRawValue("RawValue");
    rawData->SetByte("Byte");
    rawData->SetValues({"Value1", "Value2"});
    rawData->AppendGroup({"Group"});
    contact_->AddRawData(rawData, errorCode);
    EXPECT_NE((rawData->GetValue()).size(), 0);
    EXPECT_FALSE((rawData->GetByte()).empty());

    rawData->SetName(VCARD_TYPE_X_MSN);
    contact_->AddRawData(rawData, errorCode);
    rawData->SetName(VCARD_TYPE_X_YAHOO);
    contact_->AddRawData(rawData, errorCode);
    rawData->SetName(VCARD_TYPE_X_ICQ);
    contact_->AddRawData(rawData, errorCode);
    rawData->SetName(VCARD_TYPE_X_JABBER);
    contact_->AddRawData(rawData, errorCode);
    rawData->SetName(VCARD_TYPE_X_QQ);
    contact_->AddRawData(rawData, errorCode);

    EXPECT_NE((rawData->GetValue()).size(), 0);
    EXPECT_FALSE((rawData->GetByte()).empty());

    std::vector<DataShare::DataShareValuesBucket> contactDataValues;
    int32_t result = contact_->BuildContactData(1, contactDataValues);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(ContactDataTest, VCardContact_BuildContact, Function | MediumTest | Level3)
{
    std::shared_ptr<DataShare::DataShareResultSet> resultSet = std::make_shared<DataShare::DataShareResultSet>();
    EXPECT_EQ(contact_->BuildContact(nullptr), TELEPHONY_ERROR);
    EXPECT_EQ(contact_->BuildContact(resultSet), TELEPHONY_SUCCESS);
}

HWTEST_F(ContactDataTest, VCardPostalData_InitPostalData, Function | MediumTest | Level3)
{
    VCardPostalData postalData;
    std::vector<std::string> propValueList =
        {"pobox", "postalAddress", "street", "city", "region", "postCode", "country"};
    postalData.InitPostalData(propValueList, static_cast<int32_t>(PostalType::ADDR_HOME), "labelName_");
    EXPECT_STREQ((postalData.GetPOBox()).c_str(), "pobox");

    std::shared_ptr<DataShare::DataShareResultSet> resultSet = std::make_shared<DataShare::DataShareResultSet>();
    EXPECT_EQ(postalData.BuildData(nullptr), TELEPHONY_ERROR);
    EXPECT_EQ(postalData.BuildData(resultSet), TELEPHONY_SUCCESS);

    propValueList.push_back("default");
    postalData.InitPostalData(propValueList, static_cast<int32_t>(PostalType::ADDR_HOME), "labelName_");
    EXPECT_STREQ((postalData.GetPostCode()).c_str(), "postCode");
}

HWTEST_F(ContactDataTest, VCardRelationData_BuildData, Function | MediumTest | Level3)
{
    std::shared_ptr<DataShare::DataShareResultSet> resultSet = std::make_shared<DataShare::DataShareResultSet>();
    VCardRelationData relationData;
    EXPECT_EQ(relationData.BuildData(nullptr), TELEPHONY_ERROR);
    EXPECT_EQ(relationData.BuildData(resultSet), TELEPHONY_SUCCESS);
}

HWTEST_F(ContactDataTest, VCardSipData_InitSipData, Function | MediumTest | Level3)
{
    VCardSipData sipData;
    sipData.InitSipData("sip:john@example.com", static_cast<int32_t>(SipType::SIP_HOME), "Jhon");
    EXPECT_STREQ((sipData.GetAddress()).c_str(), "john@example.com");
    sipData.InitSipData("", static_cast<int32_t>(SipType::SIP_HOME), "Jhon");
    EXPECT_STREQ((sipData.GetAddress()).c_str(), "");

    sipData.InitSipData("pis:john@example.com", static_cast<int32_t>(SipType::SIP_HOME), "Jhon");
    EXPECT_STREQ((sipData.GetAddress()).c_str(), "pis:john@example.com");
}

HWTEST_F(ContactDataTest, VCardWebsiteData_BuildData, Function | MediumTest | Level3)
{
    std::shared_ptr<DataShare::DataShareResultSet> resultSet = std::make_shared<DataShare::DataShareResultSet>();
    VCardWebsiteData websiteData;
    EXPECT_EQ(websiteData.BuildData(nullptr), TELEPHONY_ERROR);
    EXPECT_EQ(websiteData.BuildData(resultSet), TELEPHONY_SUCCESS);
}

HWTEST_F(ContactDataTest, VCardDecoderV21_DecodeOne, Function | MediumTest | Level3)
{
    VCardDecoderV21 decoder;
    std::shared_ptr<VCardManager::DecodeListener> listener = std::make_shared<VCardManager::DecodeListener>();
    decoder.AddVCardDecodeListener(nullptr);

    int32_t errorCode = -1;
    decoder.Decode(errorCode);
    EXPECT_EQ(TELEPHONY_ERR_VCARD_FILE_INVALID, errorCode);
    EXPECT_FALSE(decoder.ParseItem(errorCode));

    decoder.AddVCardDecodeListener(listener);
}

HWTEST_F(ContactDataTest, VCardDecoderV21_DealParams001, Function | MediumTest | Level3)
{
    VCardDecoderV21 decoder;
    int32_t errorCode = 0;
    decoder.DealParams("TYPE=ABC", nullptr, errorCode);
    EXPECT_EQ(errorCode, 0);

    std::shared_ptr<VCardRawData> rawData = std::make_shared<VCardRawData>();
    decoder.DealParams("TYPE=ABC", rawData, errorCode);
    decoder.DealParams("TYPE=DOM", rawData, errorCode);
    decoder.DealParams("TYPE=X-DOM", rawData, errorCode);

    decoder.DealParams("VALUE=ABC", nullptr, errorCode);
    EXPECT_EQ(errorCode, 0);
    decoder.DealParams("VALUE=ABC", rawData, errorCode);
    decoder.DealParams("VALUE=URL", rawData, errorCode);
    decoder.DealParams("VALUE=X-URL", rawData, errorCode);

    decoder.DealParams("ENCODING=ABC", nullptr, errorCode);
    EXPECT_EQ(errorCode, 0);
    decoder.DealParams("ENCODING=ABC", rawData, errorCode);
    EXPECT_EQ(errorCode, TELEPHONY_ERR_VCARD_FILE_INVALID);
    errorCode = 0;
    decoder.DealParams("ENCODING=VCARD_PARAM_ENCODING_QP", rawData, errorCode);
    decoder.DealParams("ENCODING=X-VCARD_PARAM_ENCODING_QP", rawData, errorCode);
}

HWTEST_F(ContactDataTest, VCardDecoderV21_DealParams002, Function | MediumTest | Level3)
{
    VCardDecoderV21 decoder;
    int32_t errorCode = 0;
    decoder.DealParams("CHARSET=ABC", nullptr, errorCode);
    EXPECT_EQ(errorCode, 0);

    std::shared_ptr<VCardRawData> rawData = std::make_shared<VCardRawData>();
    decoder.DealParams("CHARSET=ABC", rawData, errorCode);

    decoder.DealParams("LANGUAGE=ABC", nullptr, errorCode);
    EXPECT_EQ(errorCode, 0);
    decoder.DealParams("LANGUAGE=ABC", rawData, errorCode);
    EXPECT_EQ(errorCode, TELEPHONY_ERR_VCARD_FILE_INVALID);

    errorCode = 0;
    decoder.DealParams("LANGUAGE=####-CHINESE", rawData, errorCode);
    EXPECT_EQ(errorCode, TELEPHONY_ERR_VCARD_FILE_INVALID);

    errorCode = 0;
    decoder.DealParams("LANGUAGE=ENGLISH-####", rawData, errorCode);
    EXPECT_EQ(errorCode, TELEPHONY_ERR_VCARD_FILE_INVALID);

    errorCode = 0;
    decoder.DealParams("LANGUAGE=ENGLISH-CHINESE", rawData, errorCode);
    EXPECT_EQ(errorCode, 0);

    errorCode = 0;
    decoder.DealParams("X-NAME=ENGLISH-CHINESE", rawData, errorCode);
    EXPECT_EQ(errorCode, 0);

    decoder.DealParams("NAME=ENGLISH-CHINESE", rawData, errorCode);
    EXPECT_EQ(errorCode, TELEPHONY_ERR_VCARD_FILE_INVALID);
}

HWTEST_F(ContactDataTest, VCardDecoderV21_DealEncodingQPOrNoEncodingFN, Function | MediumTest | Level3)
{
    VCardDecoderV21 decoder;
    int32_t errorCode = 0;
    decoder.DealEncodingQPOrNoEncodingFN("RawValue", nullptr, "", "", errorCode);
    EXPECT_EQ(errorCode, 0);

    std::shared_ptr<VCardRawData> rawData = std::make_shared<VCardRawData>();
    decoder.DealEncodingQPOrNoEncodingFN("example=value=\r\n", rawData, "", "", errorCode);
    EXPECT_EQ(errorCode, TELEPHONY_ERR_VCARD_FILE_INVALID);
}

HWTEST_F(ContactDataTest, VCardDecoderV21_BuildListFromValue, Function | MediumTest | Level3)
{
    VCardDecoderV21 decoder;
    EXPECT_STREQ((decoder.BuildListFromValue("test1test2test3"))[0].c_str(), "test1test2test3");
    EXPECT_STREQ((decoder.BuildListFromValue("test1;test2;test3"))[0].c_str(), "test1");
    EXPECT_STREQ((decoder.BuildListFromValue("test1\\;test2;test3"))[0].c_str(), "test1;test2");
    EXPECT_STREQ((decoder.BuildListFromValue("test1\\atest2test3"))[0].c_str(), "test1\\atest2test3");
    EXPECT_STREQ((decoder.BuildListFromValue("test1\\\\;test2\\;test3"))[0].c_str(), "test1\\");
}

HWTEST_F(ContactDataTest, VCardDecoderV21_DealAgent, Function | MediumTest | Level3)
{
    VCardDecoderV21 decoder;
    int32_t errorCode = 0;
    decoder.DealAgent(nullptr, errorCode);
    EXPECT_EQ(errorCode, 0);

    std::shared_ptr<VCardRawData> rawData = std::make_shared<VCardRawData>();
    decoder.DealAgent(rawData, errorCode);
    EXPECT_EQ(errorCode, 0);

    rawData->SetRawValue("BEGIN : VCARD some other content");
    decoder.DealAgent(rawData, errorCode);
    EXPECT_EQ(errorCode, TELEPHONY_ERR_VCARD_FILE_INVALID);
}

HWTEST_F(ContactDataTest, VCardDecoderV21_DealAdrOrgN, Function | MediumTest | Level3)
{
    VCardDecoderV21 decoder;
    int32_t errorCode = 0;
    decoder.DealAdrOrgN("RawValue", nullptr, DEFAULT_INTERMEDIATE_CHARSET, DEFAULT_IMPORT_CHARSET, errorCode);
    EXPECT_EQ(errorCode, 0);

    std::shared_ptr<VCardRawData> rawData = std::make_shared<VCardRawData>();
    decoder.DealEncodingParam(VCARD_PARAM_ENCODING_QP, rawData, errorCode);
    EXPECT_NE(errorCode, TELEPHONY_ERR_VCARD_FILE_INVALID);
}

HWTEST_F(ContactDataTest, VCardDecoderV30_UnescapeText, Function | MediumTest | Level3)
{
    VCardDecoderV30 decoder;
    EXPECT_STREQ(decoder.UnescapeText("").c_str(), "");

    EXPECT_STREQ(decoder.UnescapeText("teststring").c_str(), "teststring");
    EXPECT_STREQ(decoder.UnescapeText("test\nstring").c_str(), "test\nstring");
    EXPECT_STREQ(decoder.UnescapeText("test\\Nstring").c_str(), "test\nstring");
    EXPECT_STREQ(decoder.UnescapeText("test\\Xstring").c_str(), "testXstring");
}

HWTEST_F(ContactDataTest, VCardDecoderV30_UnescapeChar, Function | MediumTest | Level3)
{
    VCardDecoderV30 decoder;
    EXPECT_STREQ(decoder.UnescapeChar('n').c_str(), "\n");
    EXPECT_STREQ(decoder.UnescapeChar('N').c_str(), "\n");
    EXPECT_STREQ(decoder.UnescapeChar('X').c_str(), "X");
}

HWTEST_F(ContactDataTest, VCardDecoderV30_GetLine_001, Function | MediumTest | Level3)
{
    VCardDecoderV30 decoder;
    decoder.preLine_ = "";
    EXPECT_STREQ(decoder.GetLine().c_str(), "");
    decoder.preLine_ = "abc";
    EXPECT_STREQ(decoder.preLine_.c_str(), "abc");
}

HWTEST_F(ContactDataTest, VCardDecoderV30_PeekLine_001, Function | MediumTest | Level3)
{
    VCardDecoderV30 decoder;
    decoder.preLine_ = "";
    EXPECT_STREQ(decoder.GetLine().c_str(), "");
}

/**
 * @tc.name  : DealParamV30_ShouldHandleQuotedValues_WhenQuotedValuesArePresent
 * @tc.number: VCardDecoderV30Test_001
 * @tc.desc  : Test DealParamV30 method when paramValue contains quoted values
 */
HWTEST_F(ContactDataTest, VCardDecoderV30_DealParamV30_001, Function | MediumTest | Level3)
{
    VCardDecoderV30 decoder;
    std::shared_ptr<VCardRawData> rawData = std::make_shared<VCardRawData>();
    int32_t errorCode;
    std::string param = "TEST_PARAM";
    std::string paramValue = "\"quoted,value\"";
    decoder.DealParamV30(param, paramValue, rawData, errorCode);
    EXPECT_EQ(rawData->GetParameters(param).size(), 1);
}

/**
 * @tc.name  : DealParamV30_ShouldHandleNonQuotedValues_WhenNonQuotedValuesArePresent
 * @tc.number: VCardDecoderV30Test_002
 * @tc.desc  : Test DealParamV30 method when paramValue contains non-quoted values
 */
HWTEST_F(ContactDataTest, VCardDecoderV30_DealParamV30_002, Function | MediumTest | Level3)
{
    VCardDecoderV30 decoder;
    std::shared_ptr<VCardRawData> rawData = std::make_shared<VCardRawData>();
    int32_t errorCode;
    std::string param = "TEST_PARAM";
    std::string paramValue = "non,quoted,value";
    decoder.DealParamV30(param, paramValue, rawData, errorCode);
    EXPECT_EQ(rawData->GetParameters(param).size(), 3);
}

/**
 * @tc.name  : DealParamV30_ShouldHandleEmptyValues_WhenValueIsEmpty
 * @tc.number: VCardDecoderV30Test_003
 * @tc.desc  : Test DealParamV30 method when paramValue is empty
 */
HWTEST_F(ContactDataTest, VCardDecoderV30_DealParamV30_003, Function | MediumTest | Level3)
{
    VCardDecoderV30 decoder;
    std::shared_ptr<VCardRawData> rawData = std::make_shared<VCardRawData>();
    int32_t errorCode;
    std::string param = "TEST_PARAM";
    std::string paramValue = "";
    decoder.DealParamV30(param, paramValue, rawData, errorCode);
    EXPECT_EQ(rawData->GetParameters(param).size(), 0);
}

/**
 * @tc.name  : DealParamV30_ShouldHandleNonQuotedValuesWithTrailingComma_WhenTrailingCommaIsPresent
 * @tc.number: VCardDecoderV30Test_004
 * @tc.desc  : Test DealParamV30 method when paramValue contains non-quoted values with trailing comma
 */
HWTEST_F(ContactDataTest, VCardDecoderV30_DealParamV30_004, Function | MediumTest | Level3)
{
    VCardDecoderV30 decoder;
    std::shared_ptr<VCardRawData> rawData = std::make_shared<VCardRawData>();
    int32_t errorCode;
    std::string param = "TEST_PARAM";
    std::string paramValue = "non,quoted,value,";
    decoder.DealParamV30(param, paramValue, rawData, errorCode);
    EXPECT_EQ(rawData->GetParameters(param).size(), 3);
}

HWTEST_F(ContactDataTest, VCardDecoderV30_DealParams_001, Function | MediumTest | Level3)
{
    int32_t errorCode = TELEPHONY_ERR_VCARD_FILE_INVALID;
    std::shared_ptr<VCardRawData> rawData = std::make_shared<VCardRawData>();
    VCardDecoderV30 decoder;
    decoder.DealParams("invalid_params", rawData, errorCode);
    ASSERT_EQ(errorCode, TELEPHONY_ERR_VCARD_FILE_INVALID);
}

HWTEST_F(ContactDataTest, VCardDecoderV30_DealParams_002, Function | MediumTest | Level3)
{
    int32_t errorCode = TELEPHONY_SUCCESS;
    std::shared_ptr<VCardRawData> rawData = std::make_shared<VCardRawData>();
    VCardDecoderV30 decoder;
    decoder.DealParams("valid_params=value", rawData, errorCode);
    ASSERT_EQ(errorCode, TELEPHONY_SUCCESS);
}

HWTEST_F(ContactDataTest, VCardDecoderV30_DealParams_003, Function | MediumTest | Level3)
{
    int32_t errorCode = TELEPHONY_SUCCESS;
    std::shared_ptr<VCardRawData> rawData = std::make_shared<VCardRawData>();
    VCardDecoderV30 decoder;
    decoder.DealParams("invalid_params", rawData, errorCode);
    ASSERT_EQ(errorCode, TELEPHONY_SUCCESS);
}

HWTEST_F(ContactDataTest, VCardConfiguration_IsJapaneseDevice_001, Function | MediumTest | Level3)
{
    int32_t vcardType = VCardConfiguration::VCARD_TYPE_V21_JAPANESE;
    VCardConfiguration vCardConfig;
    bool result = vCardConfig.IsJapaneseDevice(vcardType);
    ASSERT_TRUE(result);
}

HWTEST_F(ContactDataTest, VCardConfiguration_IsJapaneseDevice_002, Function | MediumTest | Level3)
{
    int32_t vcardType = 2;
    VCardConfiguration vCardConfig;
    bool result = vCardConfig.IsJapaneseDevice(vcardType);
    ASSERT_FALSE(result);
}

HWTEST_F(ContactDataTest, VCardEncoder, Function | MediumTest | Level3)
{
    VCardEncoder encoder;
    int32_t errorCode = 0;
    std::vector<std::vector<int>> contactIdLists;
    std::vector<int> contactIdList;

    EXPECT_STREQ((encoder.ContructVCard(contactIdLists, errorCode).c_str()), "");
    contactIdList.push_back(1);
    contactIdLists.push_back(contactIdList);
    
    EXPECT_STREQ((encoder.ContructVCard(contactIdLists, errorCode).c_str()), "");
    EXPECT_EQ(errorCode, TELEPHONY_ERR_LOCAL_PTR_NULL);

    errorCode = 0;
    std::shared_ptr<VCardContact> contact = std::make_shared<VCardContact>();
    encoder.ContructContact(contact, 0, errorCode);
    EXPECT_EQ(errorCode, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(ContactDataTest, VCardFileUtils_Create, Function | MediumTest | Level3)
{
    VCardDecoder decoder;
    int32_t errorCode = 0;
    EXPECT_EQ(decoder.Create("", errorCode), nullptr);
    EXPECT_EQ(errorCode, TELEPHONY_ERR_VCARD_FILE_INVALID);
    EXPECT_EQ(decoder.Create("TestFile.vcf", errorCode), nullptr);
}

HWTEST_F(ContactDataTest, VCardManager_ImportLock, Function | MediumTest | Level3)
{
    VCardManager::GetInstance().listener_->OnRawDataCreated(nullptr);
    std::shared_ptr<VCardRawData> rawData = std::make_shared<VCardRawData>();
    VCardManager::GetInstance().listener_->OnRawDataCreated(rawData);

    VCardManager::GetInstance().listener_->OnOneContactStarted();
    VCardManager::GetInstance().listener_->OnRawDataCreated(rawData);

    EXPECT_EQ(VCardManager::GetInstance().ImportLock("TestPath", nullptr, 1), TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(ContactDataTest, VCardRawData_AppendParameter, Function | MediumTest | Level3)
{
    VCardRawData rawData;
    rawData.AppendParameter("testParam", "testValue");
    auto value = rawData.GetParameters("testParam");
    EXPECT_EQ(value.size(), 1);
    EXPECT_STREQ(value[0].c_str(), "testValue");

    value = rawData.GetParameters("testErrParam");
    EXPECT_EQ(value.size(), 0);

    rawData.AppendParameter("testParam", "newTestValue");
    value = rawData.GetParameters("testParam");
    EXPECT_EQ(value.size(), 2);
    EXPECT_STREQ(value[0].c_str(), "testValue");
    EXPECT_STREQ(value[1].c_str(), "newTestValue");
}

HWTEST_F(ContactDataTest, VCardRdbHelper, Function | MediumTest | Level3)
{
    VCardRdbHelper::GetInstance().SetDataHelper(nullptr);

    EXPECT_EQ(VCardRdbHelper::GetInstance().QueryRawContactMaxId(0), DB_FAILD);

    std::vector<DataShare::DataShareValuesBucket> rawContactValues;
    OHOS::DataShare::DataShareValuesBucket rawContactValue;
    EXPECT_EQ(VCardRdbHelper::GetInstance().BatchInsertRawContact(rawContactValues), DB_FAILD);
    EXPECT_EQ(VCardRdbHelper::GetInstance().InsertRawContact(rawContactValue), DB_FAILD);

    std::vector<DataShare::DataShareValuesBucket> contactDataValues;
    EXPECT_EQ(VCardRdbHelper::GetInstance().BatchInsertContactData(contactDataValues), DB_FAILD);
    EXPECT_EQ(VCardRdbHelper::GetInstance().InsertContactData(rawContactValues), DB_FAILD);

    std::vector<std::string> columns;
    OHOS::DataShare::DataSharePredicates predicates;
    EXPECT_EQ(VCardRdbHelper::GetInstance().QueryAccount(columns, predicates), nullptr);
    EXPECT_EQ(VCardRdbHelper::GetInstance().QueryContact(columns, predicates), nullptr);
    EXPECT_EQ(VCardRdbHelper::GetInstance().QueryRawContact(columns, predicates), nullptr);
    EXPECT_EQ(VCardRdbHelper::GetInstance().QueryContactData(columns, predicates), nullptr);

    DataShare::DataShareValuesBucket groupDataValue;
    EXPECT_EQ(VCardRdbHelper::GetInstance().QueryGroupData(columns, predicates), nullptr);
    EXPECT_EQ(VCardRdbHelper::GetInstance().QueryGroupId(""), DB_FAILD);
    EXPECT_EQ(VCardRdbHelper::GetInstance().InsertGroupData(groupDataValue), DB_FAILD);
}

HWTEST_F(ContactDataTest, VCardUtils_HandleCh_001, Function | MediumTest | Level3)
{
    char nextCh = 'n';
    std::string vcardType = VERSION_40;
    std::string expected = "\n";
    std::string actual = VCardUtils::HandleCh(nextCh, vcardType);
    ASSERT_EQ(expected, actual);
}

HWTEST_F(ContactDataTest, VCardUtils_HandleCh_002, Function | MediumTest | Level3)
{
    char nextCh = 'N';
    std::string vcardType = VERSION_40;
    std::string expected = "\n";
    std::string actual = VCardUtils::HandleCh(nextCh, vcardType);
    ASSERT_EQ(expected, actual);
}

HWTEST_F(ContactDataTest, VCardUtils_HandleCh_003, Function | MediumTest | Level3)
{
    char nextCh = 'n';
    std::string vcardType = VERSION_30;
    std::string expected = "\n";
    std::string actual = VCardUtils::HandleCh(nextCh, vcardType);
    ASSERT_EQ(expected, actual);
}

HWTEST_F(ContactDataTest, VCardUtils_HandleCh_004, Function | MediumTest | Level3)
{
    char nextCh = 'N';
    std::string vcardType = VERSION_30;
    std::string expected = "\n";
    std::string actual = VCardUtils::HandleCh(nextCh, vcardType);
    ASSERT_EQ(expected, actual);
}

HWTEST_F(ContactDataTest, VCardUtils_HandleCh_005, Function | MediumTest | Level3)
{
    char nextCh = '\\';
    std::string vcardType = "VERSION_21";
    std::string expected = "\\";
    std::string actual = VCardUtils::HandleCh(nextCh, vcardType);
    ASSERT_EQ(expected, actual);
}

HWTEST_F(ContactDataTest, VCardUtils_HandleCh_006, Function | MediumTest | Level3)
{
    char nextCh = ';';
    std::string vcardType = "VERSION_21";
    std::string expected = ";";
    std::string actual = VCardUtils::HandleCh(nextCh, vcardType);
    ASSERT_EQ(expected, actual);
}

HWTEST_F(ContactDataTest, VCardUtils_HandleCh_007, Function | MediumTest | Level3)
{
    char nextCh = ':';
    std::string vcardType = "VERSION_21";
    std::string expected = ":";
    std::string actual = VCardUtils::HandleCh(nextCh, vcardType);
    ASSERT_EQ(expected, actual);
}

HWTEST_F(ContactDataTest, VCardUtils_HandleCh_008, Function | MediumTest | Level3)
{
    char nextCh = ',';
    std::string vcardType = "VERSION_21";
    std::string expected = ",";
    std::string actual = VCardUtils::HandleCh(nextCh, vcardType);
    ASSERT_EQ(expected, actual);
}

HWTEST_F(ContactDataTest, VCardUtils_HandleCh_009, Function | MediumTest | Level3)
{
    char nextCh = 'a';
    std::string vcardType = "VERSION_21";
    std::string expected = "";
    std::string actual = VCardUtils::HandleCh(nextCh, vcardType);
    ASSERT_EQ(expected, actual);
}

HWTEST_F(ContactDataTest, VCardUtils_ConstructListFromValue_001, Function | MediumTest | Level3)
{
    std::string value = "";
    std::string vcardType = "VCARD";
    std::vector<std::string> expected = {""};
    std::vector<std::string> result = VCardUtils::ConstructListFromValue(value, vcardType);
    ASSERT_EQ(result, expected);
}

HWTEST_F(ContactDataTest, VCardUtils_ConstructListFromValue_002, Function | MediumTest | Level3)
{
    std::string value = "Hello;World";
    std::string vcardType = "VCARD";
    std::vector<std::string> expected = {"Hello", "HelloWorld"};
    std::vector<std::string> result = VCardUtils::ConstructListFromValue(value, vcardType);
    ASSERT_EQ(result, expected);
}

HWTEST_F(ContactDataTest, VCardUtils_ConstructListFromValue_003, Function | MediumTest | Level3)
{
    std::string value = "Hello\\;World";
    std::string vcardType = "VCARD";
    std::vector<std::string> expected = {"Hello;World"};
    std::vector<std::string> result = VCardUtils::ConstructListFromValue(value, vcardType);
    ASSERT_EQ(result, expected);
}

HWTEST_F(ContactDataTest, VCardUtils_ConstructListFromValue_004, Function | MediumTest | Level3)
{
    std::string value = "Hello;World;";
    std::string vcardType = "VCARD";
    std::vector<std::string> expected = {"Hello", "HelloWorld", "HelloWorld"};
    std::vector<std::string> result = VCardUtils::ConstructListFromValue(value, vcardType);
    ASSERT_EQ(result, expected);
}

HWTEST_F(ContactDataTest, VCardUtils_ConstructListFromValue_005, Function | MediumTest | Level3)
{
    std::string value = "Hello\\;World\\;";
    std::string vcardType = "VCARD";
    std::vector<std::string> expected = {"Hello;World;"};
    std::vector<std::string> result = VCardUtils::ConstructListFromValue(value, vcardType);
    ASSERT_EQ(result, expected);
}

HWTEST_F(ContactDataTest, VCardGroupData_BuildData, Function | MediumTest | Level3)
{
    std::shared_ptr<DataShare::DataShareResultSet> resultSet = std::make_shared<DataShare::DataShareResultSet>();
    VCardGroupData groupData;
    EXPECT_EQ(groupData.BuildData(resultSet), TELEPHONY_ERROR);
    EXPECT_EQ(groupData.BuildData(nullptr), TELEPHONY_ERROR);
}

HWTEST_F(ContactDataTest, VCardGroupData_BuildValuesBucket, Function | MediumTest | Level3)
{
    VCardGroupData groupData;
    DataShare::DataShareValuesBucket valuesBucket;
    std::string groupName = "";
    int32_t groupId = 0;
    groupData.SetGroupId(groupId);
    groupData.SetGroupName(groupName);
    EXPECT_EQ(groupData.BuildValuesBucket(valuesBucket), TELEPHONY_SUCCESS);
}

HWTEST_F(ContactDataTest, VCardGroupData_UpdateDisplayName, Function | MediumTest | Level3)
{
    VCardContact vCardContact;
    std::string family = "蕾";
    std::string middle = "";
    std::string given = "狗";
    std::string displayName = "狗雷";
    SetNameData(family, given, middle, displayName);
    vCardContact.UpdateDisplayName();
    EXPECT_EQ(nameData_->GetDisplayName(), "雷狗");
}

#endif // TEL_TEST_UNSUPPORT
} // namespace Telephony
} // namespace OHOS
