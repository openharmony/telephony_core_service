/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include <string>
#include <unistd.h>
#include <iostream>
#include "core_manager_inner.h"
#include "core_service.h"
#include "core_service_client.h"
#include "enum_convert.h"
#include "operator_config_cache.h"
#include "operator_file_parser.h"
#include "sim_state_type.h"
#include "str_convert.h"
#include "string_ex.h"
#include "tel_profile_util.h"
#include "telephony_ext_wrapper.h"
#include "gtest/gtest.h"
#include "sim_constant.h"
#include "usim_dialling_numbers_service.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
using namespace testing;

class UsimDiallingNumbersServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void UsimDiallingNumbersServiceTest::SetUpTestCase() {}

void UsimDiallingNumbersServiceTest::TearDownTestCase() {}

void UsimDiallingNumbersServiceTest::SetUp() {}

void UsimDiallingNumbersServiceTest::TearDown() {}

HWTEST_F(UsimDiallingNumbersServiceTest, SetLoadDiallingNumResult001, Function | MediumTest | Level1)
{
    auto service = std::make_shared<UsimDiallingNumbersService>();
    service->SetLoadDiallingNumResult(true);

    auto xresult = service->GetLoadDiallingNumResult();
}

HWTEST_F(UsimDiallingNumbersServiceTest, ReProcessPbrLoad001, Function | MediumTest | Level1)
{
    auto service = std::make_shared<UsimDiallingNumbersService>();
    service->fileController_ = nullptr;
    service->ReProcessPbrLoad(ELEMENTARY_FILE_PBR);

    service->fileController_ = std::make_shared<UsimFileController>(0);
    service->ReProcessPbrLoad(ELEMENTARY_FILE_PBR);
    EXPECT_TRUE(service->pbrFileLoaded_);
}

HWTEST_F(UsimDiallingNumbersServiceTest, ReProcessAdnLoad001, Function | MediumTest | Level1)
{
    auto service = std::make_shared<UsimDiallingNumbersService>();

    auto file1 = std::make_shared<UsimDiallingNumberFile>();

    auto tagAdn = std::make_shared<TagData>(0, 0, 0, 0);
    tagAdn->fileId = 1;
    auto tagExt1 = std::make_shared<TagData>(0, 0, 0, 0);
    tagExt1->fileId = 2;
    file1->fileIds_[UsimDiallingNumbersService::TAG_SIM_USIM_ADN] = tagAdn;
    file1->fileIds_[UsimDiallingNumbersService::TAG_SIM_USIM_EXT1] = tagExt1;
    service->pbrFiles_.push_back(file1);
    service->diallingNumbersHandler_ = std::make_shared<IccDiallingNumbersHandler>(nullptr);

    service->ReProcessAdnLoad(0);
    EXPECT_TRUE(service->pbrFileLoaded_);
}

HWTEST_F(UsimDiallingNumbersServiceTest, ProcessPbrLoadDone001, Function | MediumTest | Level1)
{
    auto service = std::make_shared<UsimDiallingNumbersService>();

    AppExecFwk::InnerEvent::Pointer event(nullptr, nullptr);
    service->reLoadNum_ = 0;
    service->ProcessPbrLoadDone(event);

    service->reLoadNum_ = 1;
    service->ProcessPbrLoadDone(event);

    event = AppExecFwk::InnerEvent::Get(MSG_USIM_PBR_LOAD_DONE);
    service->ProcessPbrLoadDone(event);

    service->reLoadNum_ = 0;
    service->ProcessPbrLoadDone(event);

    service->reLoadNum_ = 1;
    service->ProcessPbrLoadDone(event);

    auto multiRecord = std::make_shared<MultiRecordResult>(nullptr);
    multiRecord->exception = std::make_shared<int>(0);

    event = AppExecFwk::InnerEvent::Get(MSG_USIM_PBR_LOAD_DONE, multiRecord);
    service->ProcessPbrLoadDone(event);

    multiRecord = std::make_shared<MultiRecordResult>(nullptr);
    multiRecord->exception = nullptr;
    multiRecord->fileResults = {"file1", "file2"};

    event = AppExecFwk::InnerEvent::Get(MSG_USIM_PBR_LOAD_DONE, multiRecord);
    service->ProcessPbrLoadDone(event);
    EXPECT_TRUE(service->pbrFileLoaded_);
}

HWTEST_F(UsimDiallingNumbersServiceTest, StartLoadByPbrFiles001, Function | MediumTest | Level1)
{
    auto service = std::make_shared<UsimDiallingNumbersService>();

    service->pbrFiles_.clear();
    service->StartLoadByPbrFiles();

    auto file1 = std::make_shared<UsimDiallingNumberFile>();
    file1->parentTag_[UsimDiallingNumbersService::TAG_SIM_USIM_ANR] =
        UsimDiallingNumbersService::TYPE2_FLAG;
    auto file2 = std::make_shared<UsimDiallingNumberFile>();
    file2->parentTag_[UsimDiallingNumbersService::TAG_SIM_USIM_ANR] =
        UsimDiallingNumbersService::TYPE1_FLAG;

    service->pbrFiles_.clear();
    service->pbrFiles_.push_back(file1);
    service->pbrFiles_.push_back(file2);
    service->pbrFiles_.push_back(nullptr);
    service->StartLoadByPbrFiles();
    EXPECT_TRUE(service->pbrFileLoaded_);
}

HWTEST_F(UsimDiallingNumbersServiceTest, ProcessDiallingNumberLoadDone001, Function | MediumTest | Level1)
{
    auto service = std::make_shared<UsimDiallingNumbersService>();

    service->ProcessDiallingNumberLoadDone(AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));

    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(MSG_USIM_ADN_LOAD_DONE);
    service->ProcessDiallingNumberLoadDone(event);

    auto resultObject1 = std::make_unique<DiallingNumbersHandlerResult>(nullptr);
    resultObject1->fileID = 1;
    auto exception = std::make_shared<RadioResponseInfo>();
    resultObject1->exception = exception;
    exception->error = ErrType::ERR_GENERIC_FAILURE;
    event = AppExecFwk::InnerEvent::Get(MSG_USIM_ADN_LOAD_DONE, resultObject1);
    service->ProcessDiallingNumberLoadDone(event);

    auto resultObject2 = std::make_unique<DiallingNumbersHandlerResult>(nullptr);
    resultObject2->fileID = 2;
    resultObject2->exception = nullptr;
    resultObject2->result = nullptr;
    event = AppExecFwk::InnerEvent::Get(MSG_USIM_ADN_LOAD_DONE, resultObject2);
    service->ProcessDiallingNumberLoadDone(event);

    auto diallingNumbers = std::make_shared<std::vector<std::shared_ptr<DiallingNumbersInfo>>>();
    diallingNumbers->push_back(std::make_shared<DiallingNumbersInfo>());
    auto resultObject3 = std::make_unique<DiallingNumbersHandlerResult>(nullptr);
    resultObject3->fileID = 3;
    resultObject3->exception = nullptr;
    resultObject3->result = diallingNumbers;
    event = AppExecFwk::InnerEvent::Get(MSG_USIM_ADN_LOAD_DONE, resultObject3);
    service->ProcessDiallingNumberLoadDone(event);
    EXPECT_TRUE(service->pbrFileLoaded_);
}

HWTEST_F(UsimDiallingNumbersServiceTest, ProcessDiallingNumber2LoadDone001, Function | MediumTest | Level1)
{
    auto service = std::make_shared<UsimDiallingNumbersService>();
    service->ProcessDiallingNumber2LoadDone(AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_TRUE(service->anrs_.empty());

    service->currentIndex_ = 0;
    service->pbrFiles_.clear();
    auto pbr1 = std::make_shared<UsimDiallingNumberFile>();
    pbr1->parentTag_[UsimDiallingNumbersService::TAG_SIM_USIM_ANR] = 0;
    service->pbrFiles_.push_back(pbr1);
    auto event1 = AppExecFwk::InnerEvent::Get(MSG_USIM_ANR_LOAD_DONE, 100);
    service->ProcessDiallingNumber2LoadDone(event1);
    EXPECT_TRUE(service->anrs_[100].empty());

    service->currentIndex_ = 0;
    auto multiRecord1 = std::make_shared<MultiRecordResult>(nullptr);
    multiRecord1->fileResults = {"112233", "445566"};
    auto event2 = AppExecFwk::InnerEvent::Get(MSG_USIM_ANR_LOAD_DONE, 200, multiRecord1);
    service->ProcessDiallingNumber2LoadDone(event2);
    EXPECT_EQ(service->currentIndex_, 1);

    service->currentIndex_ = 0;
    service->pbrFiles_.clear();
    auto pbr2 = std::make_shared<UsimDiallingNumberFile>();
    pbr2->parentTag_[UsimDiallingNumbersService::TAG_SIM_USIM_ANR] = UsimDiallingNumbersService::TYPE2_FLAG;
    service->pbrFiles_.push_back(pbr2);

    service->currentIndex_ = 0;
    auto multiRecord2 = std::make_shared<MultiRecordResult>(nullptr);
    multiRecord2->fileResults = {"778899"};
    auto event3 = AppExecFwk::InnerEvent::Get(MSG_USIM_ANR_LOAD_DONE, 300, multiRecord2);
    service->ProcessDiallingNumber2LoadDone(event3);
    EXPECT_EQ(service->anrs_[300].size(), 1);
    EXPECT_EQ(service->currentIndex_, 0);
}

HWTEST_F(UsimDiallingNumbersServiceTest, FetchIapContent001, Function | MediumTest | Level1)
{
    auto service = std::make_shared<UsimDiallingNumbersService>();

    std::string emptyRecord;
    auto result = service->FetchIapContent(emptyRecord);
    EXPECT_TRUE(result.size() == 0);

    std::string validRecord = "01020304";
    auto result2 = service->FetchIapContent(validRecord);
    EXPECT_TRUE(result2.size() == 4);
}

HWTEST_F(UsimDiallingNumbersServiceTest, ProcessIapLoadDone001, Function | MediumTest | Level1)
{
    auto service = std::make_shared<UsimDiallingNumbersService>();

    service->ProcessIapLoadDone(AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));

    auto event = AppExecFwk::InnerEvent::Get(MSG_USIM_IAP_LOAD_DONE, 1);
    service->ProcessIapLoadDone(event);

    auto multiRecord = std::make_shared<MultiRecordResult>(nullptr);
    multiRecord->fileResults = {"010203", "AABBCC"};
    event = AppExecFwk::InnerEvent::Get(MSG_USIM_IAP_LOAD_DONE, 1, multiRecord);
    service->ProcessIapLoadDone(event);
    EXPECT_TRUE(service->pbrFileLoaded_);
}

HWTEST_F(UsimDiallingNumbersServiceTest, LoadPbrFiles001, Function | MediumTest | Level1)
{
    auto service = std::make_shared<UsimDiallingNumbersService>();

    service->isProcessingPbr = true;
    service->LoadPbrFiles();
    service->isProcessingPbr = false;

    service->fileController_ = nullptr;
    service->LoadPbrFiles();

    service->fileController_ = std::make_shared<UsimFileController>(0);
    service->LoadPbrFiles();
    EXPECT_TRUE(service->pbrFileLoaded_);
}

HWTEST_F(UsimDiallingNumbersServiceTest, LoadDiallingNumberFiles001, Function | MediumTest | Level1)
{
    auto service = std::make_shared<UsimDiallingNumbersService>();

    service->pbrFiles_.clear();
    service->LoadDiallingNumberFiles(0); // return 1

    auto file1 = std::make_shared<UsimDiallingNumberFile>();
    service->pbrFiles_.push_back(file1);
    service->LoadDiallingNumberFiles(0); // return 2

    auto tagAdn = std::make_shared<TagData>(0, 0, 0, 0);
    tagAdn->fileId = 1;
    auto tagExt1 = std::make_shared<TagData>(0, 0, 0, 0);
    tagExt1->fileId = 2;
    file1->fileIds_[UsimDiallingNumbersService::TAG_SIM_USIM_ADN] = tagAdn;
    file1->fileIds_[UsimDiallingNumbersService::TAG_SIM_USIM_EXT1] = tagExt1;

    service->diallingNumbersHandler_ = nullptr;
    service->LoadDiallingNumberFiles(0); // return 4 (handler_ nullptr)

    service->diallingNumbersHandler_ = std::make_shared<IccDiallingNumbersHandler>(nullptr);
    service->LoadDiallingNumberFiles(0); // return 3 (正常调用)

    file1->fileIds_[UsimDiallingNumbersService::TAG_SIM_USIM_ADN] = nullptr;
    service->LoadDiallingNumberFiles(0); // return 5 (ADN nullptr)
    EXPECT_TRUE(service->pbrFileLoaded_);
}

HWTEST_F(UsimDiallingNumbersServiceTest, LoadDiallingNumber2Files001, Function | MediumTest | Level1)
{
    auto service = std::make_shared<UsimDiallingNumbersService>();

    service->pbrFiles_.clear();
    service->LoadDiallingNumber2Files(0);

    auto file1 = std::make_shared<UsimDiallingNumberFile>();
    service->pbrFiles_.push_back(file1);
    service->LoadDiallingNumber2Files(0);

    auto tagAnr = std::make_shared<TagData>(0, 0, 0, 0);
    tagAnr->fileId = 1;
    file1->fileIds_[UsimDiallingNumbersService::TAG_SIM_USIM_ANR] = nullptr;
    service->LoadDiallingNumber2Files(0);

    file1->fileIds_[UsimDiallingNumbersService::TAG_SIM_USIM_ANR] = tagAnr;
    service->fileController_ = nullptr;
    service->LoadDiallingNumber2Files(0);

    service->fileController_ = std::make_shared<UsimFileController>(0);
    service->LoadDiallingNumber2Files(0);
    EXPECT_TRUE(service->pbrFileLoaded_);
}

HWTEST_F(UsimDiallingNumbersServiceTest, LoadIapFiles001, Function | MediumTest | Level1)
{
    auto service = std::make_shared<UsimDiallingNumbersService>();

    service->pbrFiles_.clear();
    service->LoadIapFiles(0);

    auto file1 = std::make_shared<UsimDiallingNumberFile>();
    service->pbrFiles_.push_back(file1);
    service->LoadIapFiles(0);

    auto tagIap = std::make_shared<TagData>(0, 0, 0, 0);
    tagIap->fileId = 1;
    file1->fileIds_[UsimDiallingNumbersService::TAG_SIM_USIM_IAP] = nullptr;
    service->LoadIapFiles(0);

    file1->fileIds_[UsimDiallingNumbersService::TAG_SIM_USIM_IAP] = tagIap;
    service->fileController_ = nullptr;
    service->LoadIapFiles(0);

    service->fileController_ = std::make_shared<UsimFileController>(0);
    service->LoadIapFiles(0);
    EXPECT_TRUE(service->pbrFileLoaded_);
}

HWTEST_F(UsimDiallingNumbersServiceTest, GeneratePbrFile001, Function | MediumTest | Level1)
{
    auto service = std::make_shared<UsimDiallingNumbersService>();

    std::vector<std::string> emptyRecords;
    service->GeneratePbrFile(emptyRecords);

    std::vector<std::string> shortRecord = {"A"};
    service->GeneratePbrFile(shortRecord);

    std::vector<std::string> ffRecord = {"FF1234"};
    service->GeneratePbrFile(ffRecord);

    std::vector<std::string> ffLowerRecord = {"ff5678"};
    service->GeneratePbrFile(ffLowerRecord);

    std::vector<std::string> nullPbrFileRecord = {"010203"};
    service->GeneratePbrFile(nullPbrFileRecord);

    std::vector<std::string> trueFileRecord = {
        "A82DC0034F3B12C1034F3218C5034F4214C6034F5215C4034F5B16C4034F6B1BC4034F7B1CC3034F1B17C9034F621AA905CA034F710EA"
        "A12C2034F4A03C7024F4BC8024F4CCB034F4F09FFFFFFFFFFFF"};
    service->GeneratePbrFile(trueFileRecord);

    EXPECT_FALSE(service->pbrFileLoaded_);
}

HWTEST_F(UsimDiallingNumbersServiceTest, IsValidTag001, Function | MediumTest | Level1)
{
    auto service = std::make_shared<UsimDiallingNumbersService>();

    std::map<int, std::shared_ptr<TagData>> emptyTags;
    EXPECT_FALSE(service->IsValidTag(emptyTags, 1));

    std::map<int, std::shared_ptr<TagData>> tagsWithNull;
    tagsWithNull[1] = nullptr;
    EXPECT_FALSE(service->IsValidTag(tagsWithNull, 1));

    std::map<int, std::shared_ptr<TagData>> tagsWithValid;
    tagsWithValid[1] = std::make_shared<TagData>(0, 0, 0, 0);
    EXPECT_TRUE(service->IsValidTag(tagsWithValid, 1));
}

HWTEST_F(UsimDiallingNumbersServiceTest, ProcessQueryDone001, Function | MediumTest | Level1)
{
    auto service = std::make_shared<UsimDiallingNumbersService>();
    service->pbrFiles_.clear();
    service->adns_.clear();
    service->anrs_.clear();
    service->iaps_.clear();

    // case1: ADN tag 无效
    auto pbr1 = std::make_shared<UsimDiallingNumberFile>();
    pbr1->fileIds_[UsimDiallingNumbersService::TAG_SIM_USIM_ADN] = nullptr;
    service->pbrFiles_.push_back(pbr1);
    service->ProcessQueryDone();

    // case2: ADN tag 有效但 adns_ 不存在
    auto pbr2 = std::make_shared<UsimDiallingNumberFile>();
    auto adnTag2 = std::make_shared<TagData>(0, 0, 0, 0);
    adnTag2->fileId = 1;
    pbr2->fileIds_[UsimDiallingNumbersService::TAG_SIM_USIM_ADN] = adnTag2;
    service->pbrFiles_.push_back(pbr2);
    service->ProcessQueryDone();

    // case3: ANR tag 无效
    auto pbr3 = std::make_shared<UsimDiallingNumberFile>();
    auto adnTag3 = std::make_shared<TagData>(0, 0, 0, 0);
    adnTag3->fileId = 2;
    pbr3->fileIds_[UsimDiallingNumbersService::TAG_SIM_USIM_ADN] = adnTag3;
    service->pbrFiles_.push_back(pbr3);
    service->adns_[2] = {std::make_shared<DiallingNumbersInfo>()};
    service->ProcessQueryDone();

    // case4: ANR tag 有效但 anrs_ 不存在
    auto pbr4 = std::make_shared<UsimDiallingNumberFile>();
    auto adnTag4 = std::make_shared<TagData>(0, 0, 0, 0);
    adnTag4->fileId = 3;
    auto anrTag4 = std::make_shared<TagData>(0, 0, 0, 0);
    anrTag4->fileId = 4;
    pbr4->fileIds_[UsimDiallingNumbersService::TAG_SIM_USIM_ADN] = adnTag4;
    pbr4->fileIds_[UsimDiallingNumbersService::TAG_SIM_USIM_ANR] = anrTag4;
    service->pbrFiles_.push_back(pbr4);
    service->adns_[3] = {std::make_shared<DiallingNumbersInfo>()};
    service->ProcessQueryDone();

    // case5: ANR TYPE1 正常合并
    auto pbr5 = std::make_shared<UsimDiallingNumberFile>();
    auto adnTag5 = std::make_shared<TagData>(0, 0, 0, 0);
    adnTag5->fileId = 5;
    auto anrTag5 = std::make_shared<TagData>(0, 0, 0, 0);
    anrTag5->fileId = 6;
    pbr5->fileIds_[UsimDiallingNumbersService::TAG_SIM_USIM_ADN] = adnTag5;
    pbr5->fileIds_[UsimDiallingNumbersService::TAG_SIM_USIM_ANR] = anrTag5;
    pbr5->parentTag_[UsimDiallingNumbersService::TAG_SIM_USIM_ANR] = UsimDiallingNumbersService::TYPE1_FLAG;
    service->pbrFiles_.push_back(pbr5);
    service->adns_[5] = {std::make_shared<DiallingNumbersInfo>()};
    service->anrs_[6] = {u"10086"};
    service->ProcessQueryDone();
    EXPECT_TRUE(service->pbrFileLoaded_);
}

HWTEST_F(UsimDiallingNumbersServiceTest, ProcessQueryDone002, Function | MediumTest | Level1)
{
    auto service = std::make_shared<UsimDiallingNumbersService>();
    service->pbrFiles_.clear();
    service->adns_.clear();
    service->anrs_.clear();
    service->iaps_.clear();

    // case6: ANR TYPE2, IAP tag 无效
    auto pbr6 = std::make_shared<UsimDiallingNumberFile>();
    auto adnTag6 = std::make_shared<TagData>(0, 0, 0, 0);
    adnTag6->fileId = 7;
    auto anrTag6 = std::make_shared<TagData>(0, 0, 0, 0);
    anrTag6->fileId = 8;
    pbr6->fileIds_[UsimDiallingNumbersService::TAG_SIM_USIM_ADN] = adnTag6;
    pbr6->fileIds_[UsimDiallingNumbersService::TAG_SIM_USIM_ANR] = anrTag6;
    pbr6->parentTag_[UsimDiallingNumbersService::TAG_SIM_USIM_ANR] = UsimDiallingNumbersService::TYPE2_FLAG;
    service->pbrFiles_.push_back(pbr6);
    service->adns_[7] = {std::make_shared<DiallingNumbersInfo>()};
    service->anrs_[8] = {u"12345"};
    service->ProcessQueryDone();

    // case7: ANR TYPE2, IAP tag 有效但 iaps_ 不存在
    auto pbr7 = std::make_shared<UsimDiallingNumberFile>();
    auto adnTag7 = std::make_shared<TagData>(0, 0, 0, 0);
    adnTag7->fileId = 9;
    auto anrTag7 = std::make_shared<TagData>(0, 0, 0, 0);
    anrTag7->fileId = 10;
    auto iapTag7 = std::make_shared<TagData>(0, 0, 0, 0);
    iapTag7->fileId = 11;
    pbr7->fileIds_[UsimDiallingNumbersService::TAG_SIM_USIM_ADN] = adnTag7;
    pbr7->fileIds_[UsimDiallingNumbersService::TAG_SIM_USIM_ANR] = anrTag7;
    pbr7->fileIds_[UsimDiallingNumbersService::TAG_SIM_USIM_IAP] = iapTag7;
    pbr7->parentTag_[UsimDiallingNumbersService::TAG_SIM_USIM_ANR] = UsimDiallingNumbersService::TYPE2_FLAG;
    service->pbrFiles_.push_back(pbr7);
    service->adns_[9] = {std::make_shared<DiallingNumbersInfo>()};
    service->anrs_[10] = {u"67890"};
    service->ProcessQueryDone();

    // case8: ANR TYPE2, IAP size != ADN size
    service->iaps_[11] = { {1, 2} };
    service->ProcessQueryDone();

    // case9: ANR TYPE2, IAP 映射非法
    service->iaps_[11] = { { 0xff } };
    service->ProcessQueryDone();

    // case10: ANR TYPE2, IAP 映射合法
    service->iaps_[11] = { {1} }; // 映射 anrs_[10][0]
    service->ProcessQueryDone();
    EXPECT_TRUE(service->pbrFileLoaded_);
}

HWTEST_F(UsimDiallingNumbersServiceTest, MergeNumber001, Function | MediumTest | Level1)
{
    auto service = std::make_shared<UsimDiallingNumbersService>();
    auto adn = std::make_shared<DiallingNumbersInfo>();
    adn->UpdateNumber(u"123");

    service->MergeNumber(adn, u""); // 空字符串，不修改
    service->MergeNumber(adn, u"456"); // 拼接号码
    EXPECT_TRUE(adn->GetNumber() == u"123;456");
}

HWTEST_F(UsimDiallingNumbersServiceTest, SendBackResultFullBranch, Function | MediumTest | Level1)
{
    auto service = std::make_shared<UsimDiallingNumbersService>();
    auto diallingNumbers = std::make_shared<std::vector<std::shared_ptr<DiallingNumbersInfo>>>();

    service->callers_.clear();
    service->SendBackResult(diallingNumbers); // callers_ empty

    AppExecFwk::InnerEvent::Pointer nullCaller(nullptr, nullptr);
    service->callers_.push_back(std::move(nullCaller));
    service->SendBackResult(diallingNumbers); // caller nullptr

    auto event = AppExecFwk::InnerEvent::Get(1);
    service->callers_.clear();
    service->callers_.push_back(std::move(event));
    service->SendBackResult(diallingNumbers); // owner nullptr

    auto owner = std::make_shared<UsimFileController>(0);
    auto eventWithOwner = AppExecFwk::InnerEvent::Get(1);
    eventWithOwner->SetOwner(owner);
    service->callers_.clear();
    service->callers_.push_back(std::move(eventWithOwner));
    service->SendBackResult(diallingNumbers); // 正常路径
    EXPECT_TRUE(service->pbrFileLoaded_);
}

HWTEST_F(UsimDiallingNumbersServiceTest, FetchAnrContent001, Function | MediumTest | Level1)
{
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> convert;
    auto service = std::make_shared<UsimDiallingNumbersService>();
    std::u16string result;
 
    result = service->FetchAnrContent(""); // 码流为空
    EXPECT_TRUE(result == u"");
 
    result = service->FetchAnrContent("000"); // 16 进制码流长度为奇数
    EXPECT_TRUE(result == u"");
 
    std::string str = "000500";
    str += "12345678901234567890"; // 不到 15 位
    result = service->FetchAnrContent(str);
    EXPECT_TRUE(result == u"");
 
    str = "000500";
    str += "123456789012345678901234"; // 刚好 15 位，号码不超长
    result = service->FetchAnrContent(str);
    EXPECT_TRUE(result == u"2143658709");
 
    str = "000D00";
    str += "12345678901234567890123456"; // 号码（0D: 13 * 2 = 26）超过 20 位，只截取 20 位
    result = service->FetchAnrContent(str);
    EXPECT_TRUE(result == u"21436587092143658709");
}
}
}
