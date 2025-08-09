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

HWTEST_F(UsimDiallingNumbersServiceTest, ProcessEventTest001, Function | MediumTest | Level1)
{
    auto usimDiallingNumbersService = std::make_shared<UsimDiallingNumbersService>();
    usimDiallingNumbersService->InitFuncMap();
    int32_t invalidEventId = 0xFF3807;
    auto event1 = AppExecFwk::InnerEvent::Get(MSG_USIM_PBR_LOAD_DONE);
    auto event2 = AppExecFwk::InnerEvent::Get(invalidEventId);
    usimDiallingNumbersService->ProcessEvent(event1);
    usimDiallingNumbersService->ProcessEvent(event2);
    std::unique_ptr<ControllerToFileMsg> obj;
    event1->SaveUniquePtr<std::unique_ptr<ControllerToFileMsg>>(obj);
    usimDiallingNumbersService->ProcessEvent(event1);
    EXPECT_FALSE(usimDiallingNumbersService->memberFuncMap_.empty());
}

HWTEST_F(UsimDiallingNumbersServiceTest, LoadPbrFilesTest001, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    auto usimDiallingNumbersService = std::make_shared<UsimDiallingNumbersService>();
    usimDiallingNumbersService->InitFuncMap();
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    usimDiallingNumbersService->SetFileControllerAndDiallingNumberHandler(file, handler);
    usimDiallingNumbersService->LoadPbrFiles();
    EXPECT_NE(usimDiallingNumbersService->fileController_, nullptr);
}

HWTEST_F(UsimDiallingNumbersServiceTest, ProcessDiallingNumberLoadDone001, Function | MediumTest | Level1)
{
    auto service = std::make_shared<UsimDiallingNumbersService>();
    auto event = AppExecFwk::InnerEvent::Get(MSG_USIM_ADN_LOAD_DONE);
    std::shared_ptr<UsimDiallingNumberFile> file;
    std::unique_ptr<DiallingNumbersHandlerResult> result;
    std::shared_ptr<RadioResponseInfo> responseInfo;
    
    service->pbrIndex_ = 0;
    service->pbrFiles_.clear();
    event = AppExecFwk::InnerEvent::Get(MSG_USIM_ADN_LOAD_DONE);
    service->ProcessDiallingNumberLoadDone(event);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
 
    service->pbrIndex_ = 0;
    service->pbrFiles_.clear();
    file = std::make_shared<UsimDiallingNumberFile>();
    service->pbrFiles_.push_back(file);
    event = AppExecFwk::InnerEvent::Get(MSG_USIM_ADN_LOAD_DONE);
    service->ProcessDiallingNumberLoadDone(event);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    EXPECT_TRUE(service->pbrIndex_ == 1);
}
 
HWTEST_F(UsimDiallingNumbersServiceTest, ProcessDiallingNumberLoadDone002, Function | MediumTest | Level1)
{
    auto service = std::make_shared<UsimDiallingNumbersService>();
    auto event = AppExecFwk::InnerEvent::Get(MSG_USIM_ADN_LOAD_DONE);
    std::shared_ptr<UsimDiallingNumberFile> file;
    std::unique_ptr<DiallingNumbersHandlerResult> result;
    std::shared_ptr<RadioResponseInfo> responseInfo;
 
    service->pbrIndex_ = 0;
    service->pbrFiles_.clear();
    file = std::make_shared<UsimDiallingNumberFile>();
    service->pbrFiles_.push_back(file);
    result = std::make_unique<DiallingNumbersHandlerResult>(nullptr);
    responseInfo = std::make_shared<RadioResponseInfo>();
    responseInfo->error = static_cast<Telephony::ErrType>(0);
    result->exception = static_cast<std::shared_ptr<void>>(responseInfo);
    event = AppExecFwk::InnerEvent::Get(MSG_USIM_ADN_LOAD_DONE, result);
    service->ProcessDiallingNumberLoadDone(event);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    EXPECT_TRUE(service->pbrIndex_ == 1);
 
    service->pbrIndex_ = 0;
    service->pbrFiles_.clear();
    file = std::make_shared<UsimDiallingNumberFile>();
    service->pbrFiles_.push_back(file);
    result = std::make_unique<DiallingNumbersHandlerResult>(nullptr);
    result->exception = nullptr;
    result->result = nullptr;
    event = AppExecFwk::InnerEvent::Get(MSG_USIM_ADN_LOAD_DONE, result);
    service->ProcessDiallingNumberLoadDone(event);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    EXPECT_TRUE(service->pbrIndex_ == 1);
 
    service->pbrIndex_ = 0;
    service->pbrFiles_.clear();
    file = std::make_shared<UsimDiallingNumberFile>();
    service->pbrFiles_.push_back(file);
    result = std::make_unique<DiallingNumbersHandlerResult>(nullptr);
    result->exception = nullptr;
    result->result = std::make_shared<std::vector<std::shared_ptr<DiallingNumbersInfo>>>();
    event = AppExecFwk::InnerEvent::Get(MSG_USIM_ADN_LOAD_DONE, result);
    service->ProcessDiallingNumberLoadDone(event);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    EXPECT_TRUE(service->pbrIndex_ == 1);
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
 
HWTEST_F(UsimDiallingNumbersServiceTest, LoadDiallingNumberFiles001, Function | MediumTest | Level1)
{
    auto service = std::make_shared<UsimDiallingNumbersService>();
    std::shared_ptr<UsimDiallingNumberFile> file;
    std::unique_ptr<DiallingNumbersHandlerResult> result;
    std::shared_ptr<RadioResponseInfo> responseInfo;
    bool ret;
 
    service->pbrIndex_ = 0;
    service->pbrFiles_.clear();
    ret = service->LoadDiallingNumber2Files(0);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    EXPECT_FALSE(ret);
 
    service->pbrIndex_ = 0;
    service->pbrFiles_.clear();
    file = std::make_shared<UsimDiallingNumberFile>();
    service->pbrFiles_.push_back(file);
    ret = service->LoadDiallingNumber2Files(0);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    EXPECT_FALSE(ret);
 
    service->pbrIndex_ = 0;
    service->pbrFiles_.clear();
    file = std::make_shared<UsimDiallingNumberFile>();
    file->fileIds_.emplace(UsimDiallingNumbersService::TAG_SIM_USIM_ANR, nullptr);
    service->pbrFiles_.push_back(file);
    ret = service->LoadDiallingNumber2Files(0);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    EXPECT_FALSE(ret);
 
    service->pbrIndex_ = 0;
    service->pbrFiles_.clear();
    file = std::make_shared<UsimDiallingNumberFile>();
    file->fileIds_.emplace(UsimDiallingNumbersService::TAG_SIM_USIM_ANR, std::make_shared<TagData>(0, 0, 0, 0));
    service->pbrFiles_.push_back(file);
    ret = service->LoadDiallingNumber2Files(0);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    EXPECT_FALSE(ret);
 
    service->pbrIndex_ = 0;
    service->pbrFiles_.clear();
    file = std::make_shared<UsimDiallingNumberFile>();
    file->fileIds_.emplace(UsimDiallingNumbersService::TAG_SIM_USIM_ANR, std::make_shared<TagData>(0, 0, 0, 0));
    service->pbrFiles_.push_back(file);
    service->fileController_ = std::make_shared<UsimFileController>(0);
    ret = service->LoadDiallingNumber2Files(0);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    EXPECT_TRUE(ret);
}
 
HWTEST_F(UsimDiallingNumbersServiceTest, ProcessDiallingNumber2LoadDone001, Function | MediumTest | Level1)
{
    auto service = std::make_shared<UsimDiallingNumbersService>();
    AppExecFwk::InnerEvent::Pointer event(nullptr, nullptr);
    std::shared_ptr<MultiRecordResult> recordResult = nullptr;
    std::u16string alphaTag = u"";
    std::u16string number = u"12345";
 
    service->ProcessDiallingNumber2LoadDone(event);
 
    event = AppExecFwk::InnerEvent::Get(MSG_USIM_ANR_LOAD_DONE);
    service->diallingNumbersFromAdn_.push_back(std::make_shared<DiallingNumbersInfo>(alphaTag, number));
    service->ProcessDiallingNumber2LoadDone(event);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    EXPECT_TRUE(service->diallingNumbersFromAdn_.empty());
 
    recordResult = std::make_shared<MultiRecordResult>(nullptr);
    recordResult->fileResults.push_back("000500123456789012345678901234");
    event = AppExecFwk::InnerEvent::Get(MSG_USIM_ANR_LOAD_DONE, recordResult);
    service->diallingNumbersFromAdn_.push_back(std::make_shared<DiallingNumbersInfo>(alphaTag, number));
    service->diallingNumbersFromAdn_.push_back(std::make_shared<DiallingNumbersInfo>(alphaTag, number));
    service->ProcessDiallingNumber2LoadDone(event);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    EXPECT_TRUE(service->diallingNumbersFromAdn_.empty());
 
    recordResult = std::make_shared<MultiRecordResult>(nullptr);
    recordResult->fileResults.push_back("000500123456789012345678901234");
    recordResult->fileResults.push_back("");
    event = AppExecFwk::InnerEvent::Get(MSG_USIM_ANR_LOAD_DONE, recordResult);
    service->diallingNumbersFromAdn_.push_back(std::make_shared<DiallingNumbersInfo>(alphaTag, number));
    service->diallingNumbersFromAdn_.push_back(std::make_shared<DiallingNumbersInfo>(alphaTag, number));
    service->ProcessDiallingNumber2LoadDone(event);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    EXPECT_TRUE(service->diallingNumbersFromAdn_.empty());
}

}
}
