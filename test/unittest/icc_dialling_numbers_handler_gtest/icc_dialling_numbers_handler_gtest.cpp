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
#include <gtest/gtest.h>
#include <string_ex.h>

#include "core_manager_inner.h"
#include "core_service.h"
#include "icc_dialling_numbers_handler.h"
#include "icc_dialling_numbers_manager.h"
#include "icc_file_controller.h"
#include "icc_operator_privilege_controller.h"
#include "mcc_pool.h"
#include "operator_config_cache.h"
#include "operator_config_loader.h"
#include "parcel.h"
#include "plmn_file.h"
#include "sim_account_manager.h"
#include "sim_data_type.h"
#include "sim_file_controller.h"
#include "sim_manager.h"
#include "sim_rdb_helper.h"
#include "sim_sms_manager.h"
#include "telephony_ext_wrapper.h"
#include "telephony_log_wrapper.h"
#include "usim_dialling_numbers_service.h"
#include "want.h"
#include "sim_constant.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

class DemoHandler : public AppExecFwk::EventHandler {
public:
    explicit DemoHandler(std::shared_ptr<AppExecFwk::EventRunner> &runner) : AppExecFwk::EventHandler(runner) {}
    virtual ~DemoHandler() {}
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event) {}
};

class IccDiallingNumbersHandlerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
void IccDiallingNumbersHandlerTest::SetUpTestCase() {}

void IccDiallingNumbersHandlerTest::TearDownTestCase() {}

void IccDiallingNumbersHandlerTest::SetUp() {}

void IccDiallingNumbersHandlerTest::TearDown() {}

/**
 * @tc.number   Telephony_IccDiallingNumbersHandler_001
 * @tc.name     test IccDiallingNumbersHandler
 * @tc.desc     Function test
 */
HWTEST_F(IccDiallingNumbersHandlerTest, Telephony_IccDiallingNumbersHandler_001, Function | MediumTest | Level1)
{
    int fileId = 0;
    int exId = 1;
    int indexNum = 0;
    std::string pin2Str = "";
    AppExecFwk::InnerEvent::Pointer result = AppExecFwk::InnerEvent::Get(1, 1);
    std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create("test");
    std::shared_ptr<IccFileController> iccFileController = std::make_shared<SimFileController>(1);
    auto diallingNumberHandler = std::make_shared<IccDiallingNumbersHandler>(iccFileController);
    std::shared_ptr<DiallingNumberLoadRequest> loadRequest =
        diallingNumberHandler->CreateLoadRequest(fileId, exId, indexNum, pin2Str, result);
    ASSERT_NE(loadRequest, nullptr);
}

/**
 * @tc.number   Telephony_IccDiallingNumbersHandler_002
 * @tc.name     test IccDiallingNumbersHandler
 * @tc.desc     Function test
 */
HWTEST_F(IccDiallingNumbersHandlerTest, Telephony_IccDiallingNumbersHandler_002, Function | MediumTest | Level1)
{
    int ef = 1;
    int exid = 1;
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(1, 1);
    std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create("test");
    std::shared_ptr<IccFileController> iccFileController = std::make_shared<SimFileController>(1);
    ASSERT_NE(iccFileController, nullptr);
    auto diallingNumberHandler = std::make_shared<IccDiallingNumbersHandler>(iccFileController);
    diallingNumberHandler->GetAllDiallingNumbers(ef, exid, response);
}

/**
 * @tc.number   Telephony_IccDiallingNumbersHandler_003
 * @tc.name     test IccDiallingNumbersHandler
 * @tc.desc     Function test
 */
HWTEST_F(IccDiallingNumbersHandlerTest, Telephony_IccDiallingNumbersHandler_003, Function | MediumTest | Level1)
{
    int id = 1;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(1, 1);
    ASSERT_NE(event, nullptr);
    std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create("test");
    std::shared_ptr<IccFileController> iccFileController = std::make_shared<SimFileController>(1);
    auto diallingNumberHandler = std::make_shared<IccDiallingNumbersHandler>(iccFileController);
    diallingNumberHandler->ProcessDiallingNumberAllLoadDone(event, id);
}

/**
 * @tc.number   Telephony_IccDiallingNumbersHandler_004
 * @tc.name     test IccDiallingNumbersHandler
 * @tc.desc     Function test
 */
HWTEST_F(IccDiallingNumbersHandlerTest, Telephony_IccDiallingNumbersHandler_004, Function | MediumTest | Level1)
{
    int serialId = 1;
    int fileId = 0;
    int exId = 1;
    int indexNum = 0;
    std::string pin2Str = "";
    std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create("test");
    AppExecFwk::InnerEvent::Pointer pointer = AppExecFwk::InnerEvent::Get(1, 1);
    std::shared_ptr<DiallingNumberLoadRequest> loadRequest =
        std::make_shared<DiallingNumberLoadRequest>(serialId, fileId, exId, indexNum, pin2Str, pointer);
    ASSERT_NE(loadRequest, nullptr);
    std::shared_ptr<MultiRecordResult> object = nullptr;
    std::shared_ptr<IccFileController> iccFileController = std::make_shared<SimFileController>(1);
    auto diallingNumberHandler = std::make_shared<IccDiallingNumbersHandler>(iccFileController);
    diallingNumberHandler->ProcessDiallingNumber(loadRequest, object);
}

/**
 * @tc.number   Telephony_IccDiallingNumbersHandler_005
 * @tc.name     test IccDiallingNumbersHandler
 * @tc.desc     Function test
 */
HWTEST_F(IccDiallingNumbersHandlerTest, Telephony_IccDiallingNumbersHandler_005, Function | MediumTest | Level1)
{
    std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create("test");
    AppExecFwk::InnerEvent::Pointer pointer = AppExecFwk::InnerEvent::Get(1, 1);
    std::shared_ptr<DiallingNumberLoadRequest> loadRequest = nullptr;
    std::unique_ptr<FileToControllerMsg> cmdData = pointer->GetUniqueObject<FileToControllerMsg>();
    std::shared_ptr<MultiRecordResult> object = std::make_shared<MultiRecordResult>(cmdData.get());
    ASSERT_NE(object, nullptr);
    std::shared_ptr<IccFileController> iccFileController = std::make_shared<SimFileController>(1);
    auto diallingNumberHandler = std::make_shared<IccDiallingNumbersHandler>(iccFileController);
    diallingNumberHandler->ProcessDiallingNumber(loadRequest, object);
}

/**
 * @tc.number   Telephony_IccDiallingNumbersHandler_006
 * @tc.name     test IccDiallingNumbersHandler
 * @tc.desc     Function test
 */
HWTEST_F(IccDiallingNumbersHandlerTest, Telephony_IccDiallingNumbersHandler_006, Function | MediumTest | Level1)
{
    std::u16string name = u"Hello, world!";
    int seqLength = 0;
    std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create("test");
    std::shared_ptr<IccFileController> iccFileController = std::make_shared<SimFileController>(1);
    auto diallingNumberHandler = std::make_shared<IccDiallingNumbersHandler>(iccFileController);
    std::shared_ptr<unsigned char> seqResult = diallingNumberHandler->CreateNameSequence(name, seqLength);
    ASSERT_NE(seqResult, nullptr);
}

/**
 * @tc.number   Telephony_IccDiallingNumbersHandler_007
 * @tc.name     test IccDiallingNumbersHandler
 * @tc.desc     Function test
 */
HWTEST_F(IccDiallingNumbersHandlerTest, Telephony_IccDiallingNumbersHandler_007, Function | MediumTest | Level1)
{
    std::string number = "12345678910";
    int dataLength = 0;
    std::shared_ptr<unsigned char> diallingNumber = std::make_shared<unsigned char>(42);;
    ASSERT_NE(diallingNumber, nullptr);
    std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create("test");
    std::shared_ptr<IccFileController> iccFileController = std::make_shared<SimFileController>(1);
    auto diallingNumberHandler = std::make_shared<IccDiallingNumbersHandler>(iccFileController);
    diallingNumberHandler->FillNumberFiledForDiallingNumber(diallingNumber, number, dataLength);
}

}
}