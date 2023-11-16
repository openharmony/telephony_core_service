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
#define private public
#define protected public
#include <cstdio>
#include <fstream>
#include <sstream>

#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "gtest/gtest.h"
#include "iservice_registry.h"
#include "sim_test_util.h"
#include "system_ability_definition.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "thread"
#include "vcard_constructor.h"
#include "vcard_manager.h"
#include "vcard_utils.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

namespace {
std::string CONTACT_URI = "datashare:///com.ohos.contactsdataability";
constexpr const char *TEL_FILE_NAME = "example.vcf";
std::string IMPORT_TEST_STR = R"(
BEGIN:VCARD
VERSION:2.1
N:Zhang;San;Jun;Mr.;Jr.
FN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E5=A4=96=E5=85=AC
TEL;TYPE=WORK,VOICE:1234567890
TEL;TYPE=HOME,VOICE:9876543210
TEL;TYPE=CELL,VOICE:5555555555
TEL;TYPE=FAX:9999999999
TEL;TYPE=TEXT:4444444444
TEL;TYPE=MSG:7777777777
TEL;TYPE=VIDEO:8888888888
TEL;TYPE=X-CUSTOM:1111111111
END:VCARD

BEGIN:VCARD
VERSION:2.1
N;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E6=B5=8B=E8=AF=95=4E;;;;
END:VCARD

)";
std::string INPUT_STR_TWO = R"(
BEGIN:VCARD
VERSION:2.1
N:Zhang;San;Jun;Mr.;Jr.
FN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E5=A4=96=E5=85=AC
TEL;TYPE=WORK,VOICE:1234567890
TEL;TYPE=HOME,VOICE:9876543210
TEL;TYPE=CELL,VOICE:5555555555
TEL;TYPE=FAX:9999999999
TEL;TYPE=TEXT:4444444444
TEL;TYPE=MSG:7777777777
TEL;TYPE=VIDEO:8888888888
TEL;TYPE=X-CUSTOM:1111111111
END:VCARD

BEGIN:VCARD
VERSION:2.1
N;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E6=B5=8B=E8=AF=95=4E;;;;
END:VCARD

)";

std::string INPUT_STR_THREE =
    "BEGIN:VCARD\r\nVERSION:2.1\r\nX_OHOS_CUSTOM;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:relation;="
    "E6=B5=8B=E8=AF=95;=E6=B5=8B=E8=AF=95=69=64;=E6=B5=8B=E8=AF=95=6E=61=6D=65\r\nX_OHOS_CUSTOM:"
    "relation;realationName;labelId;labelName\r\nEND:VCARD\r\n";
std::string INPUT_STR_FOUR =
    "BEGIN:VCARD\r\nVERSION:2.1\r\nX_OHOS_CUSTOM:contact_event;20230102;1;test\r\nBDAY:20230103\r\nEND:VCARD\r\n";

std::string INPUT_STR_FIVE = R"(
BEGIN:VCARD
VERSION:2.0
N;CHARSET=UTF-8:刘;小;;;
FN;CHARSET=UTF-8:刘小
ORG;CHARSET=UTF-8:开放人工智能
TITLE;CHARSET=UTF-8:AI助手
TEL;WORK;VOICE:1234567890
EMAIL;INTERNET:liuxiao@example.com
ADR;WORK;CHARSET=UTF-8:;;123 Main St;Anytown;CA;12345;USA
TEL;CELL;VOICE:9876543210
URL;WORK:http://example.com
NOTE;CHARSET=UTF-8:这是一个测试备注
REV:20220101T120000Z
END:VCARD
BEGIN:VCARD
VERSION:2.0
N;CHARSET=SHIFT_JIS:山田;太郎;;;
FN;CHARSET=SHIFT_JIS:山田太郎
ORG;CHARSET=SHIFT_JIS:オープンAI株式会社
TEL;WORK;VOICE:1234567890
EMAIL;INTERNET:"llll"
 <test@example.com>
NICKNAME:John
TEL;CELL;VOICE:9876543210
URL;WORK:http://example.com
NOTE;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E8=BF=99=E6=98=AF=E4=B8=80=E4=B8=AA=E6=B5=8B=E8=AF=95=
=E5=A4=87=E6=B3=A8
REV:20220101T120000Z
PHOTO;ENCODING=BASE64;JPEG:
5oiR54ix5oiR55qE56WW5Zu9

END:VCARD
)";
} // namespace

class VcardTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper(int32_t systemAbilityId, std::string &uri)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        TELEPHONY_LOGE("CreateDataShareHelper Get system ability mgr failed.");
        return nullptr;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    if (remoteObj == nullptr) {
        TELEPHONY_LOGE("CreateDataShareHelper GetSystemAbility Service Failed.");
        return nullptr;
    }
    return DataShare::DataShareHelper::Creator(remoteObj, uri);
}
void VcardTest::SetUpTestCase() {}

void VcardTest::TearDownTestCase() {}

void VcardTest::SetUp() {}

void VcardTest::TearDown() {}

void WriteTestData(const std::string &testStr)
{
    std::ofstream file(TEL_FILE_NAME, std::ios::trunc);
    if (file.is_open()) {
        std::stringstream ss(testStr);
        std::string line;

        while (std::getline(ss, line)) {
            file << line << std::endl;
        }
    }
    file.close();
}

void WriteTestDataWithFileName(const std::string &testStr, const std::string &fileName)
{
    std::ofstream file(fileName.c_str(), std::ios::trunc);
    if (file.is_open()) {
        std::stringstream ss(testStr);
        std::string line;

        while (std::getline(ss, line)) {
            file << line << std::endl;
        }
    }
    file.close();
}

void TestImport(const std::string &fileName)
{
    VCardManager::GetInstance().ImportLock(
        fileName, CreateDataShareHelper(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID, CONTACT_URI), 0);
}

void TestExport(std::string &filePath)
{
    DataShare::DataSharePredicates predicates;
    predicates.Between(Contact::ID, "0", "10");
    VCardManager::GetInstance().ExportLock(
        filePath, CreateDataShareHelper(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID, CONTACT_URI), predicates);
}

/**
 * @tc.number   Telephony_VcardTest_000
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_000, Function | MediumTest | Level2)
{
    AccessToken token;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        CreateDataShareHelper(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID, CONTACT_URI);
    if (dataShareHelper != nullptr) {
        TELEPHONY_LOGI("CreateDataShareHelper start test!!");
        VCardManager::GetInstance().SetDataHelper(dataShareHelper);
        WriteTestData(IMPORT_TEST_STR);
        std::vector<std::string> columns;
        OHOS::DataShare::DataSharePredicates predicates;
        predicates.Between(Contact::ID, "0", "100");
        auto resultSetBefor = VCardRdbHelper::GetInstance().QueryContact(columns, predicates);
        if (resultSetBefor == nullptr) {
            TELEPHONY_LOGE("VCardTest QueryContact failed");
        }
        int rowCountBefor = 0;
        resultSetBefor->GetRowCount(rowCountBefor);
        TELEPHONY_LOGE("VCardTest QueryContact rowCountBefor= %{public}d", rowCountBefor);
        VCardManager::GetInstance().Import(TEL_FILE_NAME, 0);
        auto resultSetAfter = VCardRdbHelper::GetInstance().QueryContact(columns, predicates);
        if (resultSetAfter == nullptr) {
            TELEPHONY_LOGE("VCardTest QueryContact failed");
        }
        int rowCountAfter = 0;
        resultSetAfter->GetRowCount(rowCountAfter);
        TELEPHONY_LOGE("VCardTest QueryContact rowCountAfter= %{public}d", rowCountAfter);
        EXPECT_EQ(((rowCountAfter - rowCountBefor) == 2), true);
    } else {
        TELEPHONY_LOGE("VCardTest CreateDataShareHelper == null");
        EXPECT_TRUE(false);
    }
}

/**
 * @tc.number   Telephony_VcardTest_101
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_101, Function | MediumTest | Level2)
{
    AccessToken token;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        CreateDataShareHelper(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID, CONTACT_URI);
    if (dataShareHelper != nullptr) {
        TELEPHONY_LOGI("CreateDataShareHelper start test!!");
        VCardManager::GetInstance().SetDataHelper(dataShareHelper);
        std::string filePath = "test";
        std::vector<std::string> columns;
        DataShare::DataSharePredicates predicates;
        predicates.EqualTo(Contact::ID, "1")->Or()->EqualTo(Contact::ID, "3");
        auto resultSet = VCardRdbHelper::GetInstance().QueryContact(columns, predicates);
        if (resultSet == nullptr) {
            TELEPHONY_LOGE("VCardTest QueryContact failed");
        }
        int rowCount = 0;
        resultSet->GetRowCount(rowCount);
        TELEPHONY_LOGE("VCardTest QueryContact rowCount= %{public}d", rowCount);
        VCardManager::GetInstance().Export(filePath, predicates);
        TELEPHONY_LOGI("VCardTest export filePath = %{public}s", filePath.c_str());
        VCardManager::GetInstance().Import(filePath, 0);
    } else {
        TELEPHONY_LOGE("VCardTest CreateDataShareHelper == null");
        EXPECT_TRUE(false);
    }
}

/**
 * @tc.number   Telephony_VcardTest_102
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_102, Function | MediumTest | Level2)
{
    AccessToken token;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        CreateDataShareHelper(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID, CONTACT_URI);
    if (dataShareHelper != nullptr) {
        TELEPHONY_LOGI("CreateDataShareHelper start test!!");
        VCardManager::GetInstance().SetDataHelper(dataShareHelper);
        std::string filePath = "test";
        std::vector<std::string> columns;
        DataShare::DataSharePredicates predicates2;
        predicates2.Between(RawContact::ID, "0", "100")->And()->EqualTo(RawContact::IS_DELETED, CONTACTS_NOT_DELETED);
        auto resultSet = VCardRdbHelper::GetInstance().QueryRawContact(columns, predicates2);
        if (resultSet == nullptr) {
            TELEPHONY_LOGE("VCardTest QueryContact failed");
        }
        int rowCount = 0;
        resultSet->GetRowCount(rowCount);
        TELEPHONY_LOGE("VCardTest QueryContact rowCount= %{public}d", rowCount);
        DataShare::DataSharePredicates predicates;
        predicates.Between(Contact::ID, "0", "100");
        VCardManager::GetInstance().Export(filePath, predicates);
        TELEPHONY_LOGI("VCardTest export filePath = %{public}s", filePath.c_str());
        int32_t errorCode;
        VCardManager::GetInstance().Decode(filePath, errorCode);
        EXPECT_EQ(errorCode, TELEPHONY_SUCCESS);
    } else {
        TELEPHONY_LOGE("VCardTest CreateDataShareHelper == null");
        EXPECT_TRUE(false);
    }
}

/**
 * @tc.number   Telephony_VcardTest_001
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_001, Function | MediumTest | Level1)
{
    std::string inputString = "BEGIN:VCARD\nN:Ando;Roid;\nEND:VCARD\n";
    WriteTestData(inputString);
    int32_t errorCode;
    VCardManager::GetInstance().Decode(TEL_FILE_NAME, errorCode);
    EXPECT_EQ(errorCode, TELEPHONY_SUCCESS);
    EXPECT_EQ(static_cast<int32_t>(VCardManager::GetInstance().listener_->contacts_.size()), 1);
}

/**
 * @tc.number   Telephony_VcardTest_002
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_002, Function | MediumTest | Level1)
{
    WriteTestData(INPUT_STR_TWO);
    int32_t errorCode;
    VCardManager::GetInstance().Decode(TEL_FILE_NAME, errorCode);
    EXPECT_EQ(errorCode, TELEPHONY_SUCCESS);
    EXPECT_EQ(static_cast<int32_t>(VCardManager::GetInstance().listener_->contacts_.size()), 2);
}

/**
 * @tc.number   Telephony_VcardTest_003
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_003, Function | MediumTest | Level1)
{
    WriteTestData(INPUT_STR_FIVE);
    int32_t errorCode;
    VCardManager::GetInstance().Decode(TEL_FILE_NAME, errorCode);
    EXPECT_EQ(errorCode, TELEPHONY_SUCCESS);
    EXPECT_EQ(static_cast<int32_t>(VCardManager::GetInstance().listener_->contacts_.size()), 2);
}

/**
 * @tc.number   Telephony_VcardTest_004
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_004, Function | MediumTest | Level1)
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
    VCardManager::GetInstance().Decode(TEL_FILE_NAME, errorCode);
    EXPECT_EQ(errorCode, TELEPHONY_SUCCESS);
    EXPECT_EQ(static_cast<int32_t>(VCardManager::GetInstance().listener_->contacts_.size()), 1);
}

/**
 * @tc.number   Telephony_VcardTest_005
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_005, Function | MediumTest | Level1)
{
    std::string inputString =
        "BEGIN:VCARD\r\nVERSION:2.1\r\nN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E6=B5=8B=E8=AF=95=31="
        "31=31=31=31=74=65=73=74;;;;\r\nFN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E6=B5=8B=E8=AF=95="
        "31=31=31=31=31=74=65=73=74\r\nEND:VCARD\r\n";
    WriteTestData(inputString);
    int32_t errorCode;
    VCardManager::GetInstance().Decode(TEL_FILE_NAME, errorCode);
    std::vector<std::shared_ptr<VCardContact>> contacts = VCardManager::GetInstance().listener_->contacts_;
    std::string name = contacts[0]->GetNameData()->GetDisplayName();
    EXPECT_EQ(name, "测试11111test");
    EXPECT_EQ(errorCode, TELEPHONY_SUCCESS);
    EXPECT_EQ(static_cast<int32_t>(contacts.size()), 1);
}

/**
 * @tc.number   Telephony_VcardTest_006
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_006, Function | MediumTest | Level1)
{
    std::string inputString = "BEGIN:VCARD\r\nVERSION:2.1\r\nN:test;;;;\r\nFN:test\r\nEND:VCARD\r\n";
    WriteTestData(inputString);
    int32_t errorCode;
    VCardManager::GetInstance().Decode(TEL_FILE_NAME, errorCode);
    std::vector<std::shared_ptr<VCardContact>> contacts = VCardManager::GetInstance().listener_->contacts_;
    std::string name = contacts[0]->GetNameData()->GetDisplayName();
    EXPECT_EQ(name, "test");
    EXPECT_EQ(errorCode, TELEPHONY_SUCCESS);
    EXPECT_EQ(static_cast<int32_t>(contacts.size()), 1);
}

/**
 * @tc.number   Telephony_VcardTest_007
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_007, Function | MediumTest | Level1)
{
    std::string inputString =
        "BEGIN:VCARD\r\nVERSION:2.1\r\nN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E6=B5=8B=E8=AF=95=46;=77=6F=77=6F=77="
        "6F;=E6=B5=8B=E8=AF=95=4D;=E6=B5=8B=E8=AF=95=50;=77=6F=77=6F=77=6F=53=75\r\nFN:test\r\nX-PHONETIC-FIRST-NAME;"
        "CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E6=B5=8B=E8=AF=95=47=56\r\nX-PHONETIC-MIDDLE-NAME:wowowowMI\r\nX-"
        "PHONETIC-LAST-NAME;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E6=B5=8B=E8=AF=95=46=50\r\nEND:VCARD\r\n";
    WriteTestData(inputString);
    int32_t errorCode;
    VCardManager::GetInstance().Decode(TEL_FILE_NAME, errorCode);
    std::vector<std::shared_ptr<VCardContact>> contacts = VCardManager::GetInstance().listener_->contacts_;

    EXPECT_EQ(contacts[0]->GetNameData()->GetDisplayName(), "test");
    EXPECT_EQ(contacts[0]->GetNameData()->GetFamily(), "测试F");
    EXPECT_EQ(contacts[0]->GetNameData()->GetGiven(), "wowowo");
    EXPECT_EQ(contacts[0]->GetNameData()->GetMiddle(), "测试M");
    EXPECT_EQ(contacts[0]->GetNameData()->GetSuffix(), "wowowoSu");
    EXPECT_EQ(contacts[0]->GetNameData()->GetPrefix(), "测试P");
    EXPECT_EQ(contacts[0]->GetNameData()->GetPhoneticFamily(), "测试FP");
    EXPECT_EQ(contacts[0]->GetNameData()->GetPhoneticGiven(), "测试GV");
    EXPECT_EQ(contacts[0]->GetNameData()->GetPhoneticMiddle(), "wowowowMI");
    EXPECT_EQ(errorCode, TELEPHONY_SUCCESS);
    EXPECT_EQ(static_cast<int32_t>(contacts.size()), 1);
}

/**
 * @tc.number   Telephony_VcardTest_008
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_008, Function | MediumTest | Level1)
{
    std::string inputString =
        "BEGIN:VCARD\r\nVERSION:2.1\r\nX_OHOS_CUSTOM;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:relation;="
        "E6=B5=8B=E8=AF=95;=E6=B5=8B=E8=AF=95=69=64;=E6=B5=8B=E8=AF=95=6E=61=6D=65\r\nX_OHOS_CUSTOM:"
        "relation;realationName;labelId;labelName\r\nEND:VCARD\r\n";
    WriteTestData(inputString);
    int32_t errorCode;
    VCardManager::GetInstance().Decode(TEL_FILE_NAME, errorCode);
    std::vector<std::shared_ptr<VCardContact>> contacts = VCardManager::GetInstance().listener_->contacts_;
    EXPECT_EQ(contacts[0]->GetRelations()[0]->GetRelationName(), "测试");
    EXPECT_EQ(contacts[0]->GetRelations()[0]->GetLabelId(), "测试id");
    EXPECT_EQ(contacts[0]->GetRelations()[0]->GetLabelName(), "测试name");
    EXPECT_EQ(contacts[0]->GetRelations()[1]->GetRelationName(), "realationName");
    EXPECT_EQ(contacts[0]->GetRelations()[1]->GetLabelId(), "labelId");
    EXPECT_EQ(contacts[0]->GetRelations()[1]->GetLabelName(), "labelName");
    EXPECT_EQ(errorCode, TELEPHONY_SUCCESS);
    EXPECT_EQ(static_cast<int32_t>(contacts.size()), 1);
    EXPECT_EQ(static_cast<int32_t>(contacts[0]->GetRelations().size()), 2);
}

/**
 * @tc.number   Telephony_VcardTest_009
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_009, Function | MediumTest | Level1)
{
    std::string inputString =
        "BEGIN:VCARD\r\nVERSION:2.1\r\nX-MSN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E6=B5=8B=E8=AF="
        "95\r\nX-AIM:test\r\nEND:VCARD\r\n";
    WriteTestData(inputString);
    int32_t errorCode;
    VCardManager::GetInstance().Decode(TEL_FILE_NAME, errorCode);
    std::vector<std::shared_ptr<VCardContact>> contacts = VCardManager::GetInstance().listener_->contacts_;

    EXPECT_EQ(contacts[0]->GetIms()[0]->GetAddress(), "测试");
    EXPECT_EQ(contacts[0]->GetIms()[0]->GetLabelId(), "1");
    EXPECT_EQ(contacts[0]->GetIms()[1]->GetAddress(), "test");
    EXPECT_EQ(contacts[0]->GetIms()[1]->GetLabelId(), "0");
    EXPECT_EQ(errorCode, TELEPHONY_SUCCESS);
    EXPECT_EQ(static_cast<int32_t>(contacts.size()), 1);
    EXPECT_EQ(static_cast<int32_t>(contacts[0]->GetIms().size()), 2);
}

std::string TestSimpleName(const std::string &name)
{
    auto nameData = std::make_shared<VCardNameData>();
    nameData->displayName_ = name;
    auto contact = std::make_shared<VCardContact>();
    contact->names_.push_back(nameData);
    auto constructor = std::make_shared<VCardConstructor>();
    auto value = constructor->ContactVCard(contact);
    return value;
}

/**
 * @tc.number   Telephony_VCardTest_Name_001
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_Name_001, Function | MediumTest | Level1)
{
    auto value = TestSimpleName("测试11111test");
    auto expectValue = "BEGIN:VCARD\r\nVERSION:2.1\r\nN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E6=B5=8B=E8=AF=95=31="
                       "31=31=31=31=74=65=73=74;;;;\r\nFN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E6=B5=8B=E8=AF=95="
                       "31=31=31=31=31=74=65=73=74\r\nEND:VCARD\r\n";
    EXPECT_EQ(value, expectValue);
    TELEPHONY_LOGE("wang Telephony_VCardTest_Name_001 value %{public}s", value.c_str());
}

/**
 * @tc.number   Telephony_VCardTest_Name_002
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_Name_002, Function | MediumTest | Level1)
{
    auto value = TestSimpleName("test");
    EXPECT_EQ(value.empty(), false);
    WriteTestData(value);
    auto expectValue = "BEGIN:VCARD\r\nVERSION:2.1\r\nN:test;;;;\r\nFN:test\r\nEND:VCARD\r\n";
    EXPECT_EQ(value, expectValue);
}

/**
 * @tc.number   Telephony_VCardTest_Name_003
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_Name_003, Function | MediumTest | Level1)
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
    auto expectValue =
        "BEGIN:VCARD\r\nVERSION:2.1\r\nN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E6=B5=8B=E8=AF=95=46;=77=6F=77=6F=77="
        "6F;=E6=B5=8B=E8=AF=95=4D;=E6=B5=8B=E8=AF=95=50;=77=6F=77=6F=77=6F=53=75\r\nFN:test\r\nX-PHONETIC-FIRST-NAME;"
        "CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E6=B5=8B=E8=AF=95=47=56\r\nX-PHONETIC-MIDDLE-NAME:wowowowMI\r\nX-"
        "PHONETIC-LAST-NAME;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E6=B5=8B=E8=AF=95=46=50\r\nEND:VCARD\r\n";
    EXPECT_EQ(value, expectValue);
}

/**
 * @tc.number   Telephony_VCardTest_Relation_001
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_Relation_001, Function | MediumTest | Level1)
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
    auto expectValue = "BEGIN:VCARD\r\nVERSION:2.1\r\nX_OHOS_CUSTOM;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:relation;="
                       "E6=B5=8B=E8=AF=95;=E6=B5=8B=E8=AF=95=69=64;=E6=B5=8B=E8=AF=95=6E=61=6D=65\r\nX_OHOS_CUSTOM:"
                       "relation;realationName;labelId;labelName\r\nEND:VCARD\r\n";
    EXPECT_EQ(value, expectValue);
}

/**
 * @tc.number   Telephony_VCardTest_Im_001
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_Im_001, Function | MediumTest | Level1)
{
    auto data1 = std::make_shared<VCardImData>();
    data1->address_ = "测试";
    data1->labelId_ = "1";
    auto data2 = std::make_shared<VCardImData>();
    data2->address_ = "test";
    data2->labelId_ = "0";
    auto data3 = std::make_shared<VCardImData>();
    data3->address_ = "testEmpty";
    data3->labelId_ = "";
    auto contact = std::make_shared<VCardContact>();
    contact->ims_.push_back(data1);
    contact->ims_.push_back(data2);
    contact->ims_.push_back(data3);
    auto constructor = std::make_shared<VCardConstructor>();
    auto value = constructor->ContactVCard(contact);
    auto expectValue = "BEGIN:VCARD\r\nVERSION:2.1\r\nX-MSN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E6=B5=8B=E8=AF="
                       "95\r\nX-AIM:test\r\nEND:VCARD\r\n";
    EXPECT_EQ(value, expectValue);
}

/**
 * @tc.number   Telephony_VCardTest_Sip_001
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_Sip_001, Function | MediumTest | Level1)
{
    auto data1 = std::make_shared<VCardSipData>();
    data1->address_ = "测试";
    data1->labelId_ = "测试id";
    data1->labelName_ = "测试name";
    auto data2 = std::make_shared<VCardSipData>();
    data2->address_ = "realationName";
    data2->labelId_ = "labelId";
    data2->labelName_ = "labelName";
    auto contact = std::make_shared<VCardContact>();
    contact->sips_.push_back(data1);
    contact->sips_.push_back(data2);
    auto constructor = std::make_shared<VCardConstructor>();
    auto value = constructor->ContactVCard(contact);
    auto expectValue = "BEGIN:VCARD\r\nVERSION:2.1\r\nX-SIP;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=73=69=70=3A=E6=B5="
                       "8B=E8=AF=95;=E6=B5=8B=E8=AF=95=69=64;=E6=B5=8B=E8=AF=95=6E=61=6D=65\r\nX-SIP:sip:realationName;"
                       "labelId;labelName\r\nEND:VCARD\r\n";
    EXPECT_EQ(value, expectValue);
}

/**
 * @tc.number   Telephony_VcardTest_010
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_010, Function | MediumTest | Level1)
{
    std::string inputString =
        "BEGIN:VCARD\r\nVERSION:2.1\r\nX-SIP;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=73=69=70=3A=E6=B5="
        "8B=E8=AF=95;=E6=B5=8B=E8=AF=95=69=64;=E6=B5=8B=E8=AF=95=6E=61=6D=65\r\nX-SIP:sip:realationName;"
        "labelId;labelName\r\nEND:VCARD\r\n";
    WriteTestData(inputString);
    int32_t errorCode;
    VCardManager::GetInstance().Decode(TEL_FILE_NAME, errorCode);
    std::vector<std::shared_ptr<VCardContact>> contacts = VCardManager::GetInstance().listener_->contacts_;

    EXPECT_EQ(contacts[0]->GetSips()[0]->GetAddress(), "测试");
    EXPECT_EQ(contacts[0]->GetSips()[0]->GetLabelId(), "测试id");
    EXPECT_EQ(contacts[0]->GetSips()[0]->GetLabelName(), "测试name");
    EXPECT_EQ(contacts[0]->GetSips()[1]->GetAddress(), "realationName");
    EXPECT_EQ(contacts[0]->GetSips()[1]->GetLabelId(), "labelId");
    EXPECT_EQ(contacts[0]->GetSips()[1]->GetLabelName(), "labelName");

    EXPECT_EQ(errorCode, TELEPHONY_SUCCESS);
    EXPECT_EQ(static_cast<int32_t>(contacts.size()), 1);
    EXPECT_EQ(static_cast<int32_t>(contacts[0]->GetSips().size()), 2);
}

/**
 * @tc.number   Telephony_VCardTest_Phone_001
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_phone_001, Function | MediumTest | Level1)
{
    auto data1 = std::make_shared<VCardPhoneData>();
    data1->number_ = "1202020";
    data1->labelId_ = "1";
    data1->labelName_ = "测试name";
    auto data2 = std::make_shared<VCardPhoneData>();
    data2->number_ = "49305484";
    data2->labelId_ = "4";
    data2->labelName_ = "labelName";
    auto data3 = std::make_shared<VCardPhoneData>();
    data3->number_ = "503330303030";
    data3->labelId_ = "0";
    data3->labelName_ = "Work";
    auto contact = std::make_shared<VCardContact>();
    contact->phones_.push_back(data1);
    contact->phones_.push_back(data2);
    contact->phones_.push_back(data3);
    auto constructor = std::make_shared<VCardConstructor>();
    auto value = constructor->ContactVCard(contact);
    auto expectValue = "BEGIN:VCARD\r\nVERSION:2.1\r\nTEL;HOME:1202020\r\nTEL;WORK;FAX:49305484\r\nTEL;X-Work:"
                       "503330303030\r\nEND:VCARD\r\n";
    EXPECT_EQ(value, expectValue);
    constructor = std::make_shared<VCardConstructor>(VCardConfiguration::VER_30);
    value = constructor->ContactVCard(contact);
    expectValue = "BEGIN:VCARD\r\nVERSION:3.0\r\nN:\r\nFN:\r\nTEL;TYPE=HOME:1202020\r\nTEL;TYPE=WORK,FAX:"
                  "49305484\r\nTEL;TYPE=X-Work:503330303030\r\nEND:VCARD\r\n";
    EXPECT_EQ(value, expectValue);
}

/**
 * @tc.number   Telephony_VcardTest_011
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_011, Function | MediumTest | Level1)
{
    std::string inputString = "BEGIN:VCARD\r\nVERSION:2.1\r\nTEL;HOME:1202020\r\nTEL;WORK;FAX:49305484\r\nTEL;X-Work:"
                              "503330303030\r\nEND:VCARD\r\n";
    WriteTestData(inputString);
    int32_t errorCode;
    VCardManager::GetInstance().Decode(TEL_FILE_NAME, errorCode);
    std::vector<std::shared_ptr<VCardContact>> contacts = VCardManager::GetInstance().listener_->contacts_;

    EXPECT_EQ(contacts[0]->GetPhones()[0]->GetNumber(), "1202020");
    EXPECT_EQ(contacts[0]->GetPhones()[0]->GetLabelId(), "1");
    EXPECT_EQ(contacts[0]->GetPhones()[0]->GetLabelName(), "");
    EXPECT_EQ(contacts[0]->GetPhones()[1]->GetNumber(), "49305484");
    EXPECT_EQ(contacts[0]->GetPhones()[1]->GetLabelId(), "4");
    EXPECT_EQ(contacts[0]->GetPhones()[1]->GetLabelName(), "");
    EXPECT_EQ(contacts[0]->GetPhones()[2]->GetNumber(), "503330303030");
    EXPECT_EQ(contacts[0]->GetPhones()[2]->GetLabelId(), "0");
    EXPECT_EQ(contacts[0]->GetPhones()[2]->GetLabelName(), "Work");

    EXPECT_EQ(errorCode, TELEPHONY_SUCCESS);
    EXPECT_EQ(static_cast<int32_t>(contacts.size()), 1);
    EXPECT_EQ(static_cast<int32_t>(contacts[0]->GetPhones().size()), 3);
}

/**
 * @tc.number   Telephony_VCardTest_Organization_001
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_Organization_001, Function | MediumTest | Level1)
{
    auto data1 = std::make_shared<VCardOrganizationData>();
    data1->company_ = "测试";
    data1->title_ = "测试title";
    auto data2 = std::make_shared<VCardOrganizationData>();
    data2->company_ = "testCompany";
    data2->title_ = "manager";
    auto contact = std::make_shared<VCardContact>();
    contact->organizations_.push_back(data1);
    contact->organizations_.push_back(data2);
    auto constructor = std::make_shared<VCardConstructor>();
    auto value = constructor->ContactVCard(contact);
    auto expectValue = "BEGIN:VCARD\r\nVERSION:2.1\r\nORG;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E6=B5=8B=E8=AF="
                       "95\r\nTITLE;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E6=B5=8B=E8=AF=95=74=69=74=6C=65\r\nORG:"
                       "testCompany\r\nTITLE:manager\r\nEND:VCARD\r\n";
    EXPECT_EQ(value, expectValue);
}

/**
 * @tc.number   Telephony_VcardTest_012
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_012, Function | MediumTest | Level1)
{
    std::string inputString =
        "BEGIN:VCARD\r\nVERSION:2.1\r\nORG;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E6=B5=8B=E8=AF="
        "95\r\nTITLE;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E6=B5=8B=E8=AF=95=74=69=74=6C=65\r\nORG:"
        "testCompany\r\nTITLE:manager\r\nEND:VCARD\r\n";
    WriteTestData(inputString);
    int32_t errorCode;
    VCardManager::GetInstance().Decode(TEL_FILE_NAME, errorCode);
    std::vector<std::shared_ptr<VCardContact>> contacts = VCardManager::GetInstance().listener_->contacts_;

    EXPECT_EQ(contacts[0]->GetOrganizations()[0]->GetCompany(), "测试");
    EXPECT_EQ(contacts[0]->GetOrganizations()[0]->GetTitle(), "测试title");
    EXPECT_EQ(contacts[0]->GetOrganizations()[1]->GetCompany(), "testCompany");
    EXPECT_EQ(contacts[0]->GetOrganizations()[1]->GetTitle(), "manager");

    EXPECT_EQ(errorCode, TELEPHONY_SUCCESS);
    EXPECT_EQ(static_cast<int32_t>(contacts.size()), 1);
    EXPECT_EQ(static_cast<int32_t>(contacts[0]->GetOrganizations().size()), 2);
}

/**
 * @tc.number   Telephony_VCardTest_Website_001
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_Website_001, Function | MediumTest | Level1)
{
    auto data1 = std::make_shared<VCardWebsiteData>();
    data1->website_ = "测试";
    data1->labelId_ = "测试labelId";
    data1->labelName_ = "测试labelName";
    auto data2 = std::make_shared<VCardWebsiteData>();
    data2->website_ = "www.test.com";
    data2->labelId_ = "1";
    data2->labelName_ = "test";
    auto contact = std::make_shared<VCardContact>();
    contact->websites_.push_back(data1);
    contact->websites_.push_back(data2);
    auto constructor = std::make_shared<VCardConstructor>();
    auto value = constructor->ContactVCard(contact);
    auto expectValue = "BEGIN:VCARD\r\nVERSION:2.1\r\nURL;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E6=B5=8B=E8=AF=95;="
                       "E6=B5=8B=E8=AF=95=6C=61=62=65=6C=49=64;=E6=B5=8B=E8=AF=95=6C=61=62=65=6C=4E=61=6D=65\r\nURL:"
                       "www.test.com;1;test\r\nEND:VCARD\r\n";
    EXPECT_EQ(value, expectValue);
}

/**
 * @tc.number   Telephony_VcardTest_013
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_013, Function | MediumTest | Level1)
{
    std::string inputString =
        "BEGIN:VCARD\r\nVERSION:2.1\r\nURL;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E6=B5=8B=E8=AF=95;="
        "E6=B5=8B=E8=AF=95=6C=61=62=65=6C=49=64;=E6=B5=8B=E8=AF=95=6C=61=62=65=6C=4E=61=6D=65\r\nURL:"
        "www.test.com;1;test\r\nEND:VCARD\r\n";
    WriteTestData(inputString);
    int32_t errorCode;
    VCardManager::GetInstance().Decode(TEL_FILE_NAME, errorCode);
    std::vector<std::shared_ptr<VCardContact>> contacts = VCardManager::GetInstance().listener_->contacts_;

    EXPECT_EQ(contacts[0]->GetWebsites()[0]->GetWebsite(), "测试");
    EXPECT_EQ(contacts[0]->GetWebsites()[0]->GetLabelId(), "测试labelId");
    EXPECT_EQ(contacts[0]->GetWebsites()[0]->GetLabelName(), "测试labelName");
    EXPECT_EQ(contacts[0]->GetWebsites()[1]->GetWebsite(), "www.test.com");
    EXPECT_EQ(contacts[0]->GetWebsites()[1]->GetLabelId(), "1");
    EXPECT_EQ(contacts[0]->GetWebsites()[1]->GetLabelName(), "test");

    EXPECT_EQ(errorCode, TELEPHONY_SUCCESS);
    EXPECT_EQ(static_cast<int32_t>(contacts.size()), 1);
    EXPECT_EQ(static_cast<int32_t>(contacts[0]->GetWebsites().size()), 2);
}

/**
 * @tc.number   Telephony_VCardTest_Photo_001
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_Photo_001, Function | MediumTest | Level1)
{
    auto data1 = std::make_shared<VCardPhotoData>();
    std::string rawBase64 = "/9j/4QoPRXhpZgAATU0AKgAAAAgADQEOAAIAAAAPAAAAqgEPAAIAAAAHAAAAugEQAAIAAAAG"
                            "AAAAwgESAAMAAAABAAEAAAEaAAUAAAABAAAAyAEbAAUAAAABAAAA0AEoAAMAAAABAAIAAAEx"
                            "AAIAAAAOAAAA2AEyAAIAAAAUAAAA5gITAAMAAAABAAEAAIKYAAIAAAAOAAAA+odpAAQAAAAB";
    data1->bytes_ = VCardUtils::DecodeBase64(rawBase64);
    auto data2 = std::make_shared<VCardPhotoData>();
    data2->bytes_ = VCardUtils::DecodeBase64("ABCE");
    auto contact = std::make_shared<VCardContact>();
    contact->photos_.push_back(data1);
    contact->photos_.push_back(data2);
    auto constructor = std::make_shared<VCardConstructor>();
    auto value = constructor->ContactVCard(contact);
    auto expectValue =
        "BEGIN:VCARD\r\nVERSION:2.1\r\nPHOTO;ENCODING=BASE64;JPEG:/9j/4QoPRXhpZgAATU0AKgAAAAgADQEOAAIAAAAPAAAAqgE\r\n "
        "PAAIAAAAHAAAAugEQAAIAAAAGAAAAwgESAAMAAAABAAEAAAEaAAUAAAABAAAAyAEbAAUAAAAB\r\n "
        "AAAA0AEoAAMAAAABAAIAAAExAAIAAAAOAAAA2AEyAAIAAAAUAAAA5gITAAMAAAABAAEAAIKYA\r\n "
        "AIAAAAOAAAA+odpAAQAAAAB\r\n\r\nEND:VCARD\r\n";
    EXPECT_EQ(value, expectValue);
}

/**
 * @tc.number   Telephony_VCardTest_Email_001
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_Email_001, Function | MediumTest | Level1)
{
    auto data1 = std::make_shared<VCardEmailData>();
    data1->address_ = "test@670.com";
    data1->displayName_ = "test";
    data1->SetLabelId("0");
    data1->labelName_ = "custom";
    auto data2 = std::make_shared<VCardEmailData>();
    data2->address_ = "test2@670.com";
    data2->displayName_ = "测试";
    data2->SetLabelId("1");
    data2->labelName_ = "lll";
    auto data3 = std::make_shared<VCardEmailData>();
    data3->address_ = "test3@670.com";
    data3->displayName_ = "test3";
    data3->SetLabelId("2");
    data3->labelName_ = "lll2";
    auto contact = std::make_shared<VCardContact>();
    contact->emails_.push_back(data1);
    contact->emails_.push_back(data2);
    contact->emails_.push_back(data3);
    auto constructor = std::make_shared<VCardConstructor>();
    auto value = constructor->ContactVCard(contact);
    auto expectValue = "BEGIN:VCARD\r\nVERSION:2.1\r\nEMAIL;X-custom:test@670.com;test\r\nEMAIL;HOME;CHARSET=UTF-8;"
                       "ENCODING=QUOTED-PRINTABLE:=74=65=73=74=32=40=36=37=30=2E=63=6F=6D;=E6=B5=8B=E8=AF=95\r\nEMAIL;"
                       "WORK:test3@670.com;test3\r\nEND:VCARD\r\n";
    EXPECT_EQ(value, expectValue);
}

/**
 * @tc.number   Telephony_VcardTest_015
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_015, Function | MediumTest | Level1)
{
    std::string inputString =
        "BEGIN:VCARD\r\nVERSION:2.1\r\nEMAIL;X-custom:test@670.com;test\r\nEMAIL;HOME;CHARSET=UTF-8;"
        "ENCODING=QUOTED-PRINTABLE:=74=65=73=74=32=40=36=37=30=2E=63=6F=6D;=E6=B5=8B=E8=AF=95\r\nEMAIL;"
        "WORK:test3@670.com;test3\r\nEND:VCARD\r\n";
    WriteTestData(inputString);
    int32_t errorCode;
    VCardManager::GetInstance().Decode(TEL_FILE_NAME, errorCode);
    std::vector<std::shared_ptr<VCardContact>> contacts = VCardManager::GetInstance().listener_->contacts_;

    EXPECT_EQ(contacts[0]->GetEmails()[0]->GetAddress(), "test@670.com");
    EXPECT_EQ(contacts[0]->GetEmails()[0]->GetDisplayName(), "test");
    EXPECT_EQ(contacts[0]->GetEmails()[0]->GetLabelId(), "0");
    EXPECT_EQ(contacts[0]->GetEmails()[0]->GetLabelName(), "custom");
    EXPECT_EQ(contacts[0]->GetEmails()[1]->GetAddress(), "test2@670.com");
    EXPECT_EQ(contacts[0]->GetEmails()[1]->GetDisplayName(), "测试");
    EXPECT_EQ(contacts[0]->GetEmails()[1]->GetLabelId(), "1");
    EXPECT_EQ(contacts[0]->GetEmails()[1]->GetLabelName(), "");
    EXPECT_EQ(contacts[0]->GetEmails()[2]->GetAddress(), "test3@670.com");
    EXPECT_EQ(contacts[0]->GetEmails()[2]->GetDisplayName(), "test3");
    EXPECT_EQ(contacts[0]->GetEmails()[2]->GetLabelId(), "2");
    EXPECT_EQ(contacts[0]->GetEmails()[2]->GetLabelName(), "");

    EXPECT_EQ(errorCode, TELEPHONY_SUCCESS);
    EXPECT_EQ(static_cast<int32_t>(contacts.size()), 1);
    EXPECT_EQ(static_cast<int32_t>(contacts[0]->GetEmails().size()), 3);
}

/**
 * @tc.number   Telephony_VCardTest_Nickname_001
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_Nickname_001, Function | MediumTest | Level1)
{
    auto data1 = std::make_shared<VCardNicknameData>();
    data1->nickname_ = "测试";
    auto data2 = std::make_shared<VCardNicknameData>();
    data2->nickname_ = "test";
    auto contact = std::make_shared<VCardContact>();
    contact->nicknames_.push_back(data1);
    contact->nicknames_.push_back(data2);
    auto constructor = std::make_shared<VCardConstructor>();
    auto value = constructor->ContactVCard(contact);
    auto expectValue = "BEGIN:VCARD\r\nVERSION:2.1\r\nX_OHOS_CUSTOM;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:nickname;="
                       "E6=B5=8B=E8=AF=95\r\nX_OHOS_CUSTOM:nickname;test\r\nEND:VCARD\r\n";
    EXPECT_EQ(value, expectValue);
}

/**
 * @tc.number   Telephony_VcardTest_016
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_016, Function | MediumTest | Level1)
{
    std::string inputString =
        "BEGIN:VCARD\r\nVERSION:2.1\r\nX_OHOS_CUSTOM;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:nickname;="
        "E6=B5=8B=E8=AF=95\r\nX_OHOS_CUSTOM:nickname;test\r\nEND:VCARD\r\n";
    WriteTestData(inputString);
    int32_t errorCode;
    VCardManager::GetInstance().Decode(TEL_FILE_NAME, errorCode);
    std::vector<std::shared_ptr<VCardContact>> contacts = VCardManager::GetInstance().listener_->contacts_;

    EXPECT_EQ(contacts[0]->GetNicknames()[0]->GetNickName(), "测试");
    EXPECT_EQ(contacts[0]->GetNicknames()[1]->GetNickName(), "test");
    EXPECT_EQ(errorCode, TELEPHONY_SUCCESS);
    EXPECT_EQ(static_cast<int32_t>(contacts.size()), 1);
    EXPECT_EQ(static_cast<int32_t>(contacts[0]->GetNicknames().size()), 2);
}

/**
 * @tc.number   Telephony_VCardTest_PostalData_001
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_PostalData_001, Function | MediumTest | Level1)
{
    auto data1 = std::make_shared<VCardPostalData>();
    data1->SetPOBox("testpobox");
    data1->SetStreet("testStreee");
    data1->SetCity("testCity");
    data1->SetRegion("testRegion");
    data1->SetPostCode("test101010");
    data1->SetCountry("ttttcountry");
    auto data2 = std::make_shared<VCardPostalData>();
    data2->SetPOBox("测试pobox");
    data2->SetStreet("测试Streee");
    data2->SetCity("测试City");
    data2->SetRegion("测试Region");
    data2->SetPostCode("101010");
    data2->SetCountry("测试ttttcountry");
    auto contact = std::make_shared<VCardContact>();
    auto data3 = std::make_shared<VCardPostalData>();
    data3->SetPostalAddress("addresss");
    auto data4 = std::make_shared<VCardPostalData>();
    data4->SetPostalAddress("测试addresss");
    contact->postals_.push_back(data1);
    contact->postals_.push_back(data2);
    contact->postals_.push_back(data3);
    contact->postals_.push_back(data4);
    auto constructor = std::make_shared<VCardConstructor>();
    auto value = constructor->ContactVCard(contact);
    auto expectValue =
        "BEGIN:VCARD\r\nVERSION:2.1\r\nADR;HOME:testpobox;;testStreee;testCity;testRegion;test101010;"
        "ttttcountry\r\nADR;HOME;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E6=B5=8B=E8=AF=95=70=6F=62=6F=78;;=E6=B5=8B="
        "E8=AF=95=53=74=72=65=65=65;=E6=B5=8B=E8=AF=95=43=69=74=79;=E6=B5=8B=E8=AF=95=52=65=67=69=6F=6E;=31=30=31=30="
        "31=30;=E6=B5=8B=E8=AF=95=74=74=74=74=63=6F=75=6E=74=72=79\r\nADR;HOME:;addresss;;;;;\r\nADR;HOME;CHARSET=UTF-"
        "8;ENCODING=QUOTED-PRINTABLE:;=E6=B5=8B=E8=AF=95=61=64=64=72=65=73=73=73;;;;;\r\nEND:VCARD\r\n";
    EXPECT_EQ(value, expectValue);
}

/**
 * @tc.number   Telephony_VcardTest_017
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_017, Function | MediumTest | Level1)
{
    std::string inputString =
        "BEGIN:VCARD\r\nVERSION:2.1\r\nADR;HOME:testpobox;;testStreee;testCity;testRegion;test101010;"
        "ttttcountry\r\nADR;HOME;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E6=B5=8B=E8=AF=95=70=6F=62=6F=78;;=E6=B5=8B="
        "E8=AF=95=53=74=72=65=65=65;=E6=B5=8B=E8=AF=95=43=69=74=79;=E6=B5=8B=E8=AF=95=52=65=67=69=6F=6E;=31=30=31=30="
        "31=30;=E6=B5=8B=E8=AF=95=74=74=74=74=63=6F=75=6E=74=72=79\r\nADR;HOME:;addresss;;;;;\r\nADR;HOME;CHARSET=UTF-"
        "8;ENCODING=QUOTED-PRINTABLE:;=E6=B5=8B=E8=AF=95=61=64=64=72=65=73=73=73;;;;;\r\nEND:VCARD\r\n";
    WriteTestData(inputString);
    int32_t errorCode;
    VCardManager::GetInstance().Decode(TEL_FILE_NAME, errorCode);
    std::vector<std::shared_ptr<VCardContact>> contacts = VCardManager::GetInstance().listener_->contacts_;

    EXPECT_EQ(contacts[0]->GetPostalDatas()[0]->GetPOBox(), "testpobox");
    EXPECT_EQ(contacts[0]->GetPostalDatas()[0]->GetStreet(), "testStreee");
    EXPECT_EQ(contacts[0]->GetPostalDatas()[0]->GetCity(), "testCity");
    EXPECT_EQ(contacts[0]->GetPostalDatas()[0]->GetRegion(), "testRegion");
    EXPECT_EQ(contacts[0]->GetPostalDatas()[0]->GetPostCode(), "test101010");
    EXPECT_EQ(contacts[0]->GetPostalDatas()[0]->GetCountry(), "ttttcountry");

    EXPECT_EQ(contacts[0]->GetPostalDatas()[1]->GetPOBox(), "测试pobox");
    EXPECT_EQ(contacts[0]->GetPostalDatas()[1]->GetStreet(), "测试Streee");
    EXPECT_EQ(contacts[0]->GetPostalDatas()[1]->GetCity(), "测试City");
    EXPECT_EQ(contacts[0]->GetPostalDatas()[1]->GetRegion(), "测试Region");
    EXPECT_EQ(contacts[0]->GetPostalDatas()[1]->GetPostCode(), "101010");
    EXPECT_EQ(contacts[0]->GetPostalDatas()[1]->GetCountry(), "测试ttttcountry");

    EXPECT_EQ(contacts[0]->GetPostalDatas()[2]->GetPostalAddress(), "addresss");
    EXPECT_EQ(contacts[0]->GetPostalDatas()[3]->GetPostalAddress(), "测试addresss");
    EXPECT_EQ(errorCode, TELEPHONY_SUCCESS);
    EXPECT_EQ(static_cast<int32_t>(contacts.size()), 1);
    EXPECT_EQ(static_cast<int32_t>(contacts[0]->GetPostalDatas().size()), 4);
}

/**
 * @tc.number   Telephony_VCardTest_EventData_001
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_EventData_001, Function | MediumTest | Level1)
{
    auto data1 = std::make_shared<VCardEventData>();
    data1->labelId_ = "1";
    data1->labelName_ = "test";
    data1->eventDate_ = "20230102";
    auto data2 = std::make_shared<VCardEventData>();
    data2->labelId_ = "3";
    data2->labelName_ = "test";
    data2->eventDate_ = "20230103";
    auto contact = std::make_shared<VCardContact>();
    contact->events_.push_back(data1);
    contact->events_.push_back(data2);
    auto constructor = std::make_shared<VCardConstructor>();
    auto value = constructor->ContactVCard(contact);
    auto expectValue =
        "BEGIN:VCARD\r\nVERSION:2.1\r\nX_OHOS_CUSTOM:contact_event;20230102;1;test\r\nBDAY:20230103\r\nEND:VCARD\r\n";
    EXPECT_EQ(value, expectValue);
}

/**
 * @tc.number   Telephony_VcardTest_018
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_018, Function | MediumTest | Level1)
{
    std::string inputString =
        "BEGIN:VCARD\r\nVERSION:2.1\r\nX_OHOS_CUSTOM:contact_event;20230102;1;test\r\nBDAY:20230103\r\nEND:VCARD\r\n";
    WriteTestData(inputString);
    int32_t errorCode;
    VCardManager::GetInstance().Decode(TEL_FILE_NAME, errorCode);
    std::vector<std::shared_ptr<VCardContact>> contacts = VCardManager::GetInstance().listener_->contacts_;

    EXPECT_EQ(contacts[0]->GetEventDatas()[0]->GetLabelId(), "1");
    EXPECT_EQ(contacts[0]->GetEventDatas()[0]->GetLabelName(), "test");
    EXPECT_EQ(contacts[0]->GetEventDatas()[0]->GetEventDate(), "20230102");

    EXPECT_EQ(contacts[0]->GetBirthdays()->GetBirthday(), "20230103");

    EXPECT_EQ(errorCode, TELEPHONY_SUCCESS);
    EXPECT_EQ(static_cast<int32_t>(contacts.size()), 1);
    EXPECT_EQ(static_cast<int32_t>(contacts[0]->GetEventDatas().size()), 1);
}

/**
 * @tc.number   Telephony_VCardTest_NoteData_001
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_NoteData_001, Function | MediumTest | Level1)
{
    auto data1 = std::make_shared<VCardNoteData>();
    data1->note_ = "testnote";
    auto data2 = std::make_shared<VCardNoteData>();
    data2->note_ = "测试";
    auto contact = std::make_shared<VCardContact>();
    contact->notes_.push_back(data1);
    contact->notes_.push_back(data2);
    auto constructor = std::make_shared<VCardConstructor>();
    auto value = constructor->ContactVCard(contact);
    auto expectValue = "BEGIN:VCARD\r\nVERSION:2.1\r\nNOTE:testnote\r\nNOTE;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:="
                       "E6=B5=8B=E8=AF=95\r\nEND:VCARD\r\n";
    EXPECT_EQ(value, expectValue);
}

/**
 * @tc.number   Telephony_VcardTest_019
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_019, Function | MediumTest | Level1)
{
    std::string inputString =
        "BEGIN:VCARD\r\nVERSION:2.1\r\nNOTE:testnote\r\nNOTE;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:="
        "E6=B5=8B=E8=AF=95\r\nEND:VCARD\r\n";
    WriteTestData(inputString);
    int32_t errorCode;
    VCardManager::GetInstance().Decode(TEL_FILE_NAME, errorCode);
    std::vector<std::shared_ptr<VCardContact>> contacts = VCardManager::GetInstance().listener_->contacts_;

    EXPECT_EQ(contacts[0]->GetNotes()[0]->GetNote(), "testnote");
    EXPECT_EQ(contacts[0]->GetNotes()[1]->GetNote(), "测试");

    EXPECT_EQ(errorCode, TELEPHONY_SUCCESS);
    EXPECT_EQ(static_cast<int32_t>(contacts.size()), 1);
    EXPECT_EQ(static_cast<int32_t>(contacts[0]->GetNotes().size()), 2);
}

/**
 * @tc.number   Telephony_VcardTest_020
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_020, Function | MediumTest | Level1)
{
    std::string inputString2 = R"(
BEGIN:VCARD
VERSION:2.1
N;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E6=B5=8B=E8=AF=95=31;;;;
FN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E6=B5=8B=E8=AF=95=31
TEL;:18770000001
END:VCARD
BEGIN:VCARD
VERSION:2.1
N;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E6=B5=8B=E8=AF=95=32;;;;
FN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=E6=B5=8B=E8=AF=95=32
TEL;:18770000002
END:VCARD
)";
    WriteTestData(inputString2);
    TELEPHONY_LOGI("Telephony_VCardTest_020 start test!!");
    VCardManager::GetInstance().Import(TEL_FILE_NAME, 0);
}

/**
 * @tc.number   Telephony_VcardTest_021
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_021, Function | MediumTest | Level1)
{
    std::string inputString2 = "";
    WriteTestData(inputString2);
    int32_t errorCode = VCardManager::GetInstance().Import(TEL_FILE_NAME, 0);
    EXPECT_EQ(errorCode, TELEPHONY_ERR_VCARD_FILE_INVALID);
}

/**
 * @tc.number   Telephony_VcardTest_022
 * @tc.name     test simple vcard
 * @tc.desc     Function test
 */
HWTEST_F(VcardTest, Telephony_VCardTest_022, Function | MediumTest | Level1)
{
    AccessToken token;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        CreateDataShareHelper(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID, CONTACT_URI);
    if (dataShareHelper != nullptr) {
        TELEPHONY_LOGI("CreateDataShareHelper start test!!");
        VCardManager::GetInstance().SetDataHelper(dataShareHelper);
        std::string filePath = "test";
        DataShare::DataSharePredicates predicates;
        predicates.EqualTo(Contact::ID, "-1");
        int32_t errorCode = VCardManager::GetInstance().Export(filePath, predicates);
        EXPECT_EQ(errorCode, TELEPHONY_ERROR);
    } else {
        TELEPHONY_LOGE("VCardTest CreateDataShareHelper == null");
        EXPECT_TRUE(false);
    }
}

HWTEST_F(VcardTest, Telephony_VCardTest_Multi_Thread_Import, Function | MediumTest | Level2)
{
    AccessToken token;
    int testNum = 20;
    int testStringNum = 25;
    std::vector<std::string> fileNames;
    std::string copiedString;
    for (int i = 0; i < testStringNum; ++i) {
        copiedString += INPUT_STR_FIVE;
    }
    for (int i = 0; i < testNum; i++) {
        std::string fileName = "TestFile_" + std::to_string(i) + ".vcf";
        WriteTestDataWithFileName(copiedString, fileName);
        fileNames.push_back(fileName);
    }

    std::vector<std::thread> threads;
    for (auto fileName : fileNames) {
        threads.emplace_back(std::thread(std::bind(TestImport, fileName)));
    }

    for (auto &thread : threads) {
        thread.join();
    }

    for (auto &fileName : fileNames) {
        std::remove(fileName.c_str());
    }
    EXPECT_EQ(static_cast<int32_t>(VCardManager::GetInstance().listener_->GetContacts().size()), 0);
}

HWTEST_F(VcardTest, Telephony_VCardTest_Multi_Thread_Export, Function | MediumTest | Level2)
{
    AccessToken token;
    int testNum = 5;
    std::vector<std::thread> threads;
    std::string fileName = "export_test";
    for (int i = 0; i < testNum; i++) {
        threads.emplace_back(std::thread(std::bind(TestExport, fileName)));
    }
    for (auto &thread : threads) {
        thread.join();
    }
    EXPECT_NE(fileName.c_str(), "test");
}

} // namespace Telephony
} // namespace OHOS
