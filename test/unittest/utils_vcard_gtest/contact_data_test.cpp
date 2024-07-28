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

#include "vcard_email_data.h"
#include "vcard_event_data.h"
#include "vcard_im_data.h"
#include "vcard_name_data.h"
#include "vcard_nickname_data.h"
#include "vcard_note_data.h"
#include "vcard_organization_data.h"
#include "vcard_phone_data.h"
#include "vcard_photo_data.h"
#include "vcard_contact.h"
#include "vcard_constant.h"
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
#endif // TEL_TEST_UNSUPPORT
} // namespace Telephony
} // namespace OHOS
