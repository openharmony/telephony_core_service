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
#include <gtest/gtest.h>
#include <string_ex.h>

#include "core_service.h"
#include "icc_file_controller.h"
#include "runner_pool.h"
#include "sim_data_type.h"
#include "sim_file_controller.h"
#include "sim_manager.h"
#include "sim_rdb_helper.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

namespace {
constexpr int32_t SLOT_ID = 0;
} // namespace

class DemoHandler : public AppExecFwk::EventHandler {
public:
    explicit DemoHandler(std::shared_ptr<AppExecFwk::EventRunner> &runner) : AppExecFwk::EventHandler(runner) {}
    virtual ~DemoHandler() {}
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event) {}
};

class SimRilBranchTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
void SimRilBranchTest::SetUpTestCase() {}

void SimRilBranchTest::TearDownTestCase() {}

void SimRilBranchTest::SetUp() {}

void SimRilBranchTest::TearDown() {}

/**
 * @tc.number   Telephony_tel_ril_manager_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(SimRilBranchTest, Telephony_tel_ril_manager_001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    telRilManager->DeInit();
    telRilManager->ReduceRunningLock();
    telRilManager->SendAckAndLock();
    int32_t slotFaild = -1;
    telRilManager->GetTelRilSms(slotFaild);
    telRilManager->GetTelRilSim(slotFaild);
    telRilManager->GetTelRilModem(slotFaild);
    telRilManager->GetTelRilData(slotFaild);
    telRilManager->GetTelRilNetwork(slotFaild);
    telRilManager->GetTelRilCall(slotFaild);
    int32_t slot_0 = SLOT_ID;
    telRilManager->GetTelRilSms(slot_0);
    telRilManager->GetTelRilSim(slot_0);
    telRilManager->GetTelRilModem(slot_0);
    telRilManager->GetTelRilData(slot_0);
    telRilManager->GetTelRilNetwork(slot_0);
    telRilManager->GetTelRilCall(slot_0);
    std::shared_ptr<TelRilCall> emptyCall = nullptr;
    telRilManager->telRilCall_.push_back(emptyCall);
    telRilManager->ResetRilInterface();
    std::shared_ptr<ObserverHandler> observerHandler = nullptr;
    telRilManager->observerHandler_.push_back(observerHandler);
    std::shared_ptr<AppExecFwk::EventHandler> observerCallBack = nullptr;
    int32_t what = 0;
    int32_t *obj = 0;
    telRilManager->RegisterCoreNotify(slot_0, observerCallBack, what, obj);
    telRilManager->UnRegisterCoreNotify(slot_0, observerCallBack, what);
    telRilManager->rilInterface_ = nullptr;
    ASSERT_TRUE(telRilManager->DisConnectRilInterface());
}

/**
 * @tc.number   Telephony_IccFileController_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(SimRilBranchTest, Telephony_IccFileController_001, Function | MediumTest | Level1)
{
    std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create("test");
    std::shared_ptr<IccFileController> iccFileController = std::make_shared<SimFileController>(runner, 1);
    auto event = AppExecFwk::InnerEvent::Get(0);
    iccFileController->ProcessReadBinary(event);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> object = std::make_unique<Telephony::IccFromRilMsg>(holder);
    auto event1 = AppExecFwk::InnerEvent::Get(0, object);
    auto event01 = AppExecFwk::InnerEvent::Get(0, object);
    auto event2 = AppExecFwk::InnerEvent::Get(0, object);
    iccFileController->ProcessReadBinary(event1);
    int fileId = 0;
    int size = 0;
    std::string path = "";
    int fileNum = 0;
    std::string data = "";
    int dataLength = 0;
    std::string pin2 = "";
    int *val = nullptr;
    iccFileController->ObtainBinaryFile(fileId, event01);
    iccFileController->ObtainBinaryFile(fileId, size, event2);
    iccFileController->ObtainLinearFixedFile(fileId, path, fileNum, event);
    iccFileController->ObtainAllLinearFixedFile(fileId, path, event);
    iccFileController->ObtainLinearFileSize(fileId, path, event);
    iccFileController->UpdateLinearFixedFile(fileId, path, fileNum, data, dataLength, pin2, event);
    iccFileController->UpdateLinearFixedFile(fileId, fileNum, data, dataLength, pin2, event);
    iccFileController->UpdateBinaryFile(fileId, data, dataLength, event);
    auto telRilManager = std::make_shared<TelRilManager>();
    iccFileController->telRilManager_ = telRilManager;
    auto event3 = AppExecFwk::InnerEvent::Get(0, object);
    auto event4 = AppExecFwk::InnerEvent::Get(0, object);
    iccFileController->ObtainBinaryFile(fileId, event3);
    iccFileController->ObtainBinaryFile(fileId, size, event4);
    iccFileController->ObtainLinearFixedFile(fileId, path, fileNum, event);
    iccFileController->UpdateLinearFixedFile(fileId, path, fileNum, data, dataLength, pin2, event);
    iccFileController->UpdateLinearFixedFile(fileId, fileNum, data, dataLength, pin2, event);
    iccFileController->UpdateBinaryFile(fileId, data, dataLength, event);
    std::vector<std::string> strValue;
    IccFileData *fd = nullptr;
    iccFileController->SendResponse(holder, fd);
    auto event5 = AppExecFwk::InnerEvent::Get(0);
    iccFileController->SendEfLinearResult(event5, val, size);
    auto event6 = AppExecFwk::InnerEvent::Get(0);
    iccFileController->SendMultiRecordResult(event6, strValue);
    unsigned char *data1;
    iccFileController->ParseFileSize(val, size, data1);
    iccFileController->IsValidSizeData(data1);
    iccFileController->GetFileAndDataSize(data1, size, size);
    ASSERT_TRUE(iccFileController->BuildCallerInfo(0, 0, 0, holder) != nullptr);
}

/**
 * @tc.number   Telephony_SimManager_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(SimRilBranchTest, Telephony_SimManager_001, Function | MediumTest | Level1)
{
    std::shared_ptr<ITelRilManager> telRilManager = nullptr;
    auto simManager = std::make_shared<SimManager>(telRilManager);
    RunnerPool::GetInstance().commonRunner_ = nullptr;
    simManager->InitSingleSimObject();
    simManager->slotCount_ = 1;
    int32_t slotId;
    simManager->SetPrimarySlotId(SLOT_ID);
    std::u16string testU = u"";
    simManager->SetShowNumber(SLOT_ID, testU);
    simManager->GetShowNumber(SLOT_ID, testU);
    simManager->GetDefaultVoiceSimId(slotId);
    simManager->GetDefaultSmsSlotId();
    simManager->slotCount_ = 1;
    int32_t dsdsMode = 0;
    int32_t slotCount = 1;
    std::string testS = "";
    simManager->GetDsdsMode(dsdsMode);
    simManager->stkManager_.resize(slotCount);
    simManager->simFileManager_.resize(slotCount);
    simManager->SendCallSetupRequestResult(SLOT_ID, true);
    simManager->GetSimGid2(SLOT_ID);
    simManager->GetOpName(SLOT_ID, testU);
    simManager->GetOpKey(SLOT_ID, testU);
    simManager->GetOpKeyExt(SLOT_ID, testU);
    simManager->GetSimTeleNumberIdentifier(SLOT_ID);
    simManager->ObtainSpnCondition(SLOT_ID, false, testS);

    simManager->slotCount_ = 0;
    simManager->GetPrimarySlotId(slotId);
    EXPECT_GT(simManager->GetDefaultSmsSlotId(), TELEPHONY_PERMISSION_ERROR);
}
} // namespace Telephony
} // namespace OHOS
