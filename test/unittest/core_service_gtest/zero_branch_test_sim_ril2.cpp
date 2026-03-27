/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>
#include <string_ex.h>

#include "core_manager_inner.h"
#include "core_service.h"
#include "mock_datashare_helper.h"
#include "icc_dialling_numbers_handler.h"
#include "icc_dialling_numbers_manager.h"
#include "icc_file_controller.h"
#include "icc_operator_privilege_controller.h"
#include "mcc_pool.h"
#include "operator_config_cache.h"
#include "operator_config_loader.h"
#include "operator_config_hisysevent.h"
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
#include "sim_file_parse.h"
#include "usim_file_controller.h"
#include "tel_ril_manager.h"

namespace OHOS {
namespace Telephony {
using namespace testing;
using namespace testing::ext;

class SimRilBranchTest2 : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
void SimRilBranchTest2::SetUpTestCase() {}

void SimRilBranchTest2::TearDownTestCase() {}

void SimRilBranchTest2::SetUp() {}

void SimRilBranchTest2::TearDown() {}

class IIccFileExtImpl : public IIccFileExt {
public:
    IIccFileExtImpl() = default;
    ~IIccFileExtImpl() = default;
    void SetIccFile(std::shared_ptr<OHOS::Telephony::IIccFileExt> &iccFile) override
    {
    }
};

HWTEST_F(SimRilBranchTest2, Telephony_IccFileController_Expand001, Function | MediumTest | Level1)
{
    std::shared_ptr<IccFileController> iccFileController = std::make_shared<SimFileController>(1);

    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_OBTAIN_SIZE_OF_LINEAR_ELEMENTARY_FILE_DONE);
    iccFileController->ProcessEvent(event);
    auto event2 = AppExecFwk::InnerEvent::Get(MSG_SIM_OBTAIN_SIZE_OF_FIXED_ELEMENTARY_FILE_DONE);
    iccFileController->ProcessEvent(event2);
    auto event3 = AppExecFwk::InnerEvent::Get(MSG_SIM_OBTAIN_INVALID_RECORD_OF_FIXED_ELEMENTARY_FILE_DONE);
    iccFileController->ProcessEvent(event3);
    auto event4 = AppExecFwk::InnerEvent::Get(MSG_SIM_OBTAIN_SIZE_OF_TRANSPARENT_ELEMENTARY_FILE_DONE);
    iccFileController->ProcessEvent(event4);
    auto event5 = AppExecFwk::InnerEvent::Get(MSG_SIM_OBTAIN_FIXED_ELEMENTARY_FILE_DONE);
    iccFileController->ProcessEvent(event5);
    auto event6 = AppExecFwk::InnerEvent::Get(MSG_SIM_OBTAIN_ICON_DONE);
    iccFileController->ProcessEvent(event6);

    iccFileController->ProcessLinearRecordSize(event);
    std::shared_ptr<IccControllerHolder> holderNullptr = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holderNullptr);
    auto event7 = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    iccFileController->ProcessLinearRecordSize(event7);
    std::shared_ptr<IccControllerHolder> holder = std::make_shared<IccControllerHolder>(0);
    holder->fileLoaded.reset();
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg2 = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg2->fileData.resultData = "123456781234567812345678";
    auto event8 = AppExecFwk::InnerEvent::Get(0, rcvMsg2);
    iccFileController->ProcessLinearRecordSize(event8);

    iccFileController->telRilManager_.reset();
    iccFileController->SendFixedRecordRequest(holder);
    iccFileController->telRilManager_ = std::make_shared<TelRilManager>();
    holder->isUseSeek = true;
    iccFileController->SendFixedRecordRequest(holder);
    EXPECT_TRUE(holder->isUseSeek == true);
}

HWTEST_F(SimRilBranchTest2, Telephony_IccFileController_Expand002, Function | MediumTest | Level1)
{
    std::shared_ptr<IccFileController> iccFileController = std::make_shared<SimFileController>(1);
    iccFileController->telRilManager_ = std::make_shared<TelRilManager>();

    std::shared_ptr<IccControllerHolder> holderNullptr = nullptr;
    std::shared_ptr<IccControllerHolder> holder = std::make_shared<IccControllerHolder>(0);
    holder->fileLoaded = AppExecFwk::InnerEvent::Get(MSG_SIM_OBTAIN_SIZE_OF_LINEAR_ELEMENTARY_FILE_DONE);
    holder->fileLoaded->SetOwner(nullptr);

    iccFileController->ProcessRecordSize(holder->fileLoaded);
    {
        std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holderNullptr);
        auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
        iccFileController->ProcessRecordSize(event);
    }
    {
        std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
        rcvMsg->fileData.resultData = "";
        auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
        iccFileController->ProcessRecordSize(event);
    }
    {
        std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
        rcvMsg->fileData.resultData = "1234567812345678";
        auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
        iccFileController->ProcessRecordSize(event);
    }

    iccFileController->ProcessInvalidRecord(holder->fileLoaded);
    {
        std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holderNullptr);
        auto event7 = AppExecFwk::InnerEvent::Get(0, rcvMsg);
        iccFileController->ProcessInvalidRecord(event7);
    }
    {
        std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
        rcvMsg->fileData.resultData = "12345678";
        auto event7 = AppExecFwk::InnerEvent::Get(0, rcvMsg);
        holder->fileNum = 0;
        holder->countFiles = 100;
        iccFileController->ProcessInvalidRecord(event7);
    }
    EXPECT_TRUE(iccFileController->telRilManager_ != nullptr);
}

HWTEST_F(SimRilBranchTest2, Telephony_IccFileController_Expand003, Function | MediumTest | Level1)
{
    std::shared_ptr<IccFileController> iccFileController = std::make_shared<SimFileController>(1);
    iccFileController->telRilManager_ = std::make_shared<TelRilManager>();
    std::shared_ptr<IccControllerHolder> holderNullptr = nullptr;
    std::shared_ptr<IccControllerHolder> holder = std::make_shared<IccControllerHolder>(0);
    holder->fileLoaded = AppExecFwk::InnerEvent::Get(MSG_SIM_OBTAIN_SIZE_OF_LINEAR_ELEMENTARY_FILE_DONE);
    holder->fileLoaded->SetOwner(nullptr);
    iccFileController->ProcessReadRecord(holder->fileLoaded);
    {
        std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holderNullptr);
        auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
        iccFileController->ProcessReadRecord(event);
    }
    {
        std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
        auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
        holder->getAllFile = true;
        iccFileController->ProcessReadRecord(event);
    }
    {
        std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
        auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
        holder->fileNum = 1;
        holder->countFiles = 9999;
        iccFileController->ProcessReadRecord(event);
    }
    {
        std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
        auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
        holder->getAllFile = false;
        iccFileController->ProcessReadRecord(event);
    }
    {
        std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
        auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
        iccFileController->ProcessReadBinary(event);
    }
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_OBTAIN_SIZE_OF_LINEAR_ELEMENTARY_FILE_DONE);
    iccFileController->ObtainLinearFixedFile(0, 0, event);
    iccFileController->ObtainAllLinearFixedFile(0, "", event, true);
    iccFileController->ObtainLinearFileSize(0, "", event);
    iccFileController->ObtainLinearFileSize(0, event);
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holderNullptr);
    iccFileController->SendResponse(holder, &rcvMsg->fileData);
    holder->fileLoaded->SetOwner(iccFileController);
    iccFileController->SendResponse(holder, &rcvMsg->fileData);
    EXPECT_TRUE(iccFileController->telRilManager_ != nullptr);
}

HWTEST_F(SimRilBranchTest2, Telephony_IccFileController_Expand004, Function | MediumTest | Level1)
{
    std::shared_ptr<IccFileController> iccFileController = std::make_shared<SimFileController>(1);
    std::shared_ptr<IccControllerHolder> holder = std::make_shared<IccControllerHolder>(0);
    holder->fileLoaded = AppExecFwk::InnerEvent::Get(MSG_SIM_OBTAIN_SIZE_OF_LINEAR_ELEMENTARY_FILE_DONE);
    {
        std::unique_ptr<EfLinearResult> EfLinear = std::make_unique<EfLinearResult>(nullptr);
        auto event = AppExecFwk::InnerEvent::Get(0, EfLinear);
        event->SetOwner(iccFileController);
        int intData[] = {1, 2, 3, 4, 5, 6, 7, 8};
        iccFileController->SendEfLinearResult(event, intData, 8);
    }
    {
        std::unique_ptr<EfLinearResult> EfLinear = std::make_unique<EfLinearResult>(nullptr);
        auto event = AppExecFwk::InnerEvent::Get(0, EfLinear);
        event->SetOwner(iccFileController);
        std::vector<std::string> strData = {"123", "456", "789"};
        iccFileController->SendMultiRecordResult(event, strData, 0);
    }
    const unsigned char cData[] = {'1', '2', '3', '4', '5', '6', '\0'};
    int dataSize = 0;
    iccFileController->GetDataSize(nullptr, dataSize);
    iccFileController->GetDataSize(cData, dataSize);
    {
        std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
        auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
        holder->fileLoaded->SetOwner(iccFileController);
        iccFileController->ProcessErrorResponse(event);
    }
    {
        std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
        auto event7 = AppExecFwk::InnerEvent::Get(0, rcvMsg);
        holder->fileLoaded->SetOwner(nullptr);
        iccFileController->ProcessErrorResponse(event7);
    }
    {
        std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
        auto event7 = AppExecFwk::InnerEvent::Get(0, rcvMsg);
        holder->fileLoaded.reset();
        iccFileController->ProcessErrorResponse(event7);
    }
    EXPECT_FALSE(iccFileController->IsValidBinarySizeData(nullptr) == true);
}

HWTEST_F(SimRilBranchTest2, Telephony_IccFileController_Expand005, Function | MediumTest | Level1)
{
    std::shared_ptr<IccFileController> iccFileController = std::make_shared<SimFileController>(1);
    std::shared_ptr<IccControllerHolder> holderNullptr = nullptr;
    std::shared_ptr<IccControllerHolder> holder = std::make_shared<IccControllerHolder>(0);

    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holderNullptr);
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_FALSE(iccFileController->ProcessErrorResponse(event) == true);

    rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    iccFileController->ProcessErrorResponse(event);

    rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holderNullptr);
    event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    iccFileController->ProcessBinarySize(event);
}

HWTEST_F(SimRilBranchTest2, Telephony_SimFile_Expand001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    auto simFile = std::make_shared<SimFile>(simStateManager);

    simFile->ProcessIccRefresh(ElementaryFile::ELEMENTARY_FILE_MBDN);
    simFile->ProcessIccRefresh(ElementaryFile::ELEMENTARY_FILE_MAILBOX_CPHS);
    simFile->ProcessIccRefresh(ElementaryFile::ELEMENTARY_FILE_CSP_CPHS);
    simFile->ProcessIccRefresh(ElementaryFile::ELEMENTARY_FILE_FDN);
    simFile->ProcessIccRefresh(ElementaryFile::ELEMENTARY_FILE_MSISDN);
    simFile->ProcessIccRefresh(ElementaryFile::ELEMENTARY_FILE_CFIS);
    simFile->ProcessFileLoaded(false);
    simStateManager->Init(0);
    simStateManager->simStateHandle_->externalType_ = CardType::UNKNOWN_CARD;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(0);
    simFile->ProcessIccReady(event);
    simFile->fileController_.reset();
    simFile->ProcessIccLocked(event);

    std::shared_ptr<IIccFileExt> iiccFileExt = std::make_shared<IIccFileExtImpl>();
    simFile->SetIccFile(iiccFileExt);

    TELEPHONY_EXT_WRAPPER.InitTelephonyExtWrapper();
    simFile->LoadSimOtherFile();
    simFile->StartObtainSpn();
    simFile->ProcessSpnGeneral(event);
    simFile->ProcessSpnCphs(event);
    auto objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->spn_ = "";
    simFile->ProcessSpnCphs(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->spn_ = "1234";
    simFile->ProcessSpnCphs(event);
    TELEPHONY_EXT_WRAPPER.DeInitTelephonyExtWrapper();

    simFile->spnStatus_ = SimFile::SpnStatus::OBTAIN_SPN_NONE;
    simFile->ObtainSpnPhase(false, event);
    event.reset();
    EXPECT_TRUE(simFile->ProcessObtainLiLanguage(event) == true);
}

HWTEST_F(SimRilBranchTest2, Telephony_SimFile_Expand002, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    auto simFile = std::make_shared<SimFile>(simStateManager);

    simFile->fileController_ = std::make_shared<SimFileController>(1);
    auto objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->resultData = "";
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessObtainLiLanguage(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->resultData = "1234";
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessObtainLiLanguage(event);

    event.reset();
    simFile->ProcessObtainPlLanguage(event);
    simFile->AnalysisBcdPlmn("", "");
    simFile->ProcessElementaryFileCsp("");
    simFile->ProcessSmses("");
    simFile->ProcessSms("");
    EXPECT_TRUE(simFile->ProcessObtainGid1Done(event) == true);
    simFile->ProcessObtainGid2Done(event);
    simFile->ProcessGetMsisdnDone(event);
    simFile->ProcessSetMsisdnDone(event);
    simFile->ProcessGetSpdiDone(event);

    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->exception = std::make_shared<int>(100);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessObtainGid1Done(event);
    event = AppExecFwk::InnerEvent::Get(0);
    simFile->ProcessObtainGid2Done(event);

    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->exception = std::make_shared<int>(100);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessSetMsisdnDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessSetMsisdnDone(event);
}

HWTEST_F(SimRilBranchTest2, Telephony_SimFile_Expand003, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    auto simFile = std::make_shared<SimFile>(simStateManager);
    simFile->fileController_ = std::make_shared<SimFileController>(1);
    auto objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetSpdiDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->exception = std::make_shared<int>(100);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetSpdiDone(event);
    event.reset();
    simFile->ProcessGetCfisDone(event);
    simFile->ProcessGetMbiDone(event);
    simFile->ProcessGetMbdnDone(event);
    simFile->ProcessGetCphsMailBoxDone(event);
    EXPECT_TRUE(simFile->ProcessGetMwisDone(event) == true);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->resultData = "1234";
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetCfisDone(event);

    event = AppExecFwk::InnerEvent::Get(0);
    simFile->ProcessGetMbiDone(event);
    simFile->ProcessGetMbdnDone(event);
    simFile->ProcessGetCphsMailBoxDone(event);

    auto diallingNumbersInfo = std::make_shared<DiallingNumbersInfo>();

    TELEPHONY_EXT_WRAPPER.InitTelephonyExtWrapper();
    auto objectUniqueResult = std::make_unique<DiallingNumbersHandlerResult>(nullptr);
    diallingNumbersInfo->name_ = u"1234";
    objectUniqueResult->result = diallingNumbersInfo;
    event = AppExecFwk::InnerEvent::Get(0, objectUniqueResult);
    simFile->ProcessGetMbdnDone(event);
    objectUniqueResult = std::make_unique<DiallingNumbersHandlerResult>(nullptr);
    objectUniqueResult->exception = std::make_shared<int>(100);
    event = AppExecFwk::InnerEvent::Get(0, objectUniqueResult);
    simFile->ProcessGetCphsMailBoxDone(event);
    objectUniqueResult = std::make_unique<DiallingNumbersHandlerResult>(nullptr);
    event = AppExecFwk::InnerEvent::Get(0, objectUniqueResult);
    simFile->ProcessGetCphsMailBoxDone(event);
    objectUniqueResult = std::make_unique<DiallingNumbersHandlerResult>(nullptr);
    objectUniqueResult->result = diallingNumbersInfo;
    event = AppExecFwk::InnerEvent::Get(0, objectUniqueResult);
    simFile->ProcessGetCphsMailBoxDone(event);
    TELEPHONY_EXT_WRAPPER.DeInitTelephonyExtWrapper();
}

HWTEST_F(SimRilBranchTest2, Telephony_SimFile_Expand004, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    auto simFile = std::make_shared<SimFile>(simStateManager);
    simFile->fileController_ = std::make_shared<SimFileController>(1);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(0);
    simFile->ProcessGetMwisDone(event);
    simFile->ProcessVoiceMailCphs(event);
    simFile->ProcessGetIccIdDone(event);

    auto objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetMwisDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->resultData = "1234";
    objectUnique->exception = std::make_shared<int>(100);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetMwisDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->resultData = "1234";
    simFile->ProcessGetMwisDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessVoiceMailCphs(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->resultData = "1234";
    objectUnique->exception = std::make_shared<int>(100);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessVoiceMailCphs(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->resultData = "1234";
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->voiceMailCount_ = DEFAULT_VOICE_MAIL_COUNT;
    simFile->ProcessVoiceMailCphs(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetIccIdDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->exception = std::make_shared<int>(100);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->iccId_ = "";
    simFile->reloadIccidCount_ = 1;
    simFile->ProcessVoiceMailCphs(event);
    event.reset();
    simFile->ProcessVoiceMailCphs(event);
    EXPECT_TRUE(simFile->ProcessGetIccIdDone(event) == true);
}

HWTEST_F(SimRilBranchTest2, Telephony_SimFile_Expand005, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    auto simFile = std::make_shared<SimFile>(simStateManager);
    simFile->telRilManager_ = telRilManager;
    simFile->fileController_ = std::make_shared<SimFileController>(1);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(0);
    simFile->ProcessReloadIccid(event);
    simFile->ProcessReloadImsi(event);
    simFile->ProcessObtainIMSIDone(event);
    simFile->ProcessGetCffDone(event);
    simFile->ProcessGetAdDone(event);
    auto sharedStr = std::make_shared<std::string>("");
    event = AppExecFwk::InnerEvent::Get(0, sharedStr);
    simFile->ProcessObtainIMSIDone(event);
    sharedStr = std::make_shared<std::string>("1234");
    event = AppExecFwk::InnerEvent::Get(0, sharedStr);
    simFile->ProcessObtainIMSIDone(event);
    auto objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetCffDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->resultData = "1234";
    objectUnique->exception = std::make_shared<int>(100);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetCffDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->resultData = "1234";
    simFile->callForwardingStatus = CALL_FORWARDING_STATUS_UNKNOWN;
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetCffDone(event);

    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->resultData = "1234";
    objectUnique->exception = std::make_shared<int>(100);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetAdDone(event);

    event.reset();
    simFile->ProcessObtainIMSIDone(event);
    simFile->ProcessGetCffDone(event);
    EXPECT_TRUE(simFile->ProcessGetAdDone(event) == true);
}

HWTEST_F(SimRilBranchTest2, Telephony_SimFile_Expand006, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    auto simFile = std::make_shared<SimFile>(simStateManager);
    simFile->fileController_ = std::make_shared<SimFileController>(1);
    simFile->CheckMncLen("", 0, 0, 0, true);
    simFile->CheckMncLen("", 0, 0, 0, false);

    simFile->indiaMcc_.clear();
    simFile->IsIndiaMcc("");

    simFile->lengthOfMnc_ = 1;
    simFile->OnMccMncLoaded("1234");

    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(0);
    simFile->ProcessSmsOnSim(event);
    simFile->ProcessGetAllSmsDone(event);
    simFile->ProcessGetSmsDone(event);

    auto objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessSmsOnSim(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->exception = std::make_shared<int>(100);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessSmsOnSim(event);

    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetAllSmsDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->exception = std::make_shared<int>(100);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetAllSmsDone(event);

    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->exception = std::make_shared<int>(100);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetSmsDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetSmsDone(event);

    event.reset();
    simFile->ProcessSmsOnSim(event);
    simFile->ProcessGetAllSmsDone(event);
    EXPECT_TRUE(simFile->ProcessGetSmsDone(event) == false);
}

HWTEST_F(SimRilBranchTest2, Telephony_SimFile_Expand007, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    auto simFile = std::make_shared<SimFile>(simStateManager);
    simFile->fileController_ = std::make_shared<SimFileController>(1);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(0);
    simFile->ProcessGetPlmnActDone(event);
    simFile->ProcessGetOplmnActDone(event);
    simFile->ProcessGetInfoCphs(event);
    simFile->ProcessGetSstDone(event);
    auto objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->exception = std::make_shared<int>(100);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetPlmnActDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetPlmnActDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->exception = std::make_shared<int>(100);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetOplmnActDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetOplmnActDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->exception = std::make_shared<int>(100);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetInfoCphs(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetInfoCphs(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->exception = std::make_shared<int>(100);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetSstDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetSstDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->resultData = "1234";
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetSstDone(event);
    event.reset();
    simFile->ProcessGetPlmnActDone(event);
    simFile->ProcessGetOplmnActDone(event);
    simFile->ProcessGetInfoCphs(event);
    EXPECT_TRUE(simFile->ProcessGetSstDone(event) == true);
}

HWTEST_F(SimRilBranchTest2, Telephony_SimFile_Expand008, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    auto simFile = std::make_shared<SimFile>(simStateManager);
    simFile->fileController_ = std::make_shared<SimFileController>(1);
    auto objectShared = std::make_unique<MultiRecordResult>(nullptr);
    objectShared->fileResults = {"1234", "4567"};
    AppExecFwk::InnerEvent::Pointer event2 = AppExecFwk::InnerEvent::Get(0, objectShared);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(0);
    simFile->ProcessGetPnnDone(event);
    simFile->ProcessGetOplDone(event);
    simFile->ProcessGetSpnCphsDone(event);
    simFile->ProcessGetSpnShortCphsDone(event);
    simFile->ProcessUpdateDone(event);
    simFile->ProcessSetCphsMailbox(event);
    auto objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetPnnDone(event);
    simFile->ProcessGetPnnDone(event2);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetOplDone(event);
    simFile->ProcessGetOplDone(event2);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetSpnCphsDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetSpnShortCphsDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->exception = std::make_shared<int>(100);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetOpl5gDone(event);
    simFile->ProcessGetOpl5gDone(event2);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->exception = std::make_shared<int>(100);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessUpdateDone(event);
    event.reset();
    simFile->ProcessGetPnnDone(event);
    simFile->ProcessGetOplDone(event);
    simFile->ProcessSetCphsMailbox(event);
    EXPECT_TRUE(simFile->ProcessUpdateDone(event) == false);
}

HWTEST_F(SimRilBranchTest2, Telephony_SimFile_Expand009, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    auto simFile = std::make_shared<SimFile>(simStateManager);
    simFile->fileController_ = std::make_shared<SimFileController>(1);
    simFile->diallingNumberHandler_ = std::make_shared<IccDiallingNumbersHandler>(simFile->fileController_);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(0);
    simFile->ProcessGetHplmActDone(event);
    simFile->ProcessGetEhplmnDone(event);
    simFile->ProcessGetFplmnDone(event);
    simFile->ProcessSetMbdn(event);
    simFile->ProcessObtainSpnPhase(event);

    auto objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->exception = std::make_shared<int>(100);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetHplmActDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetHplmActDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->exception = std::make_shared<int>(100);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetEhplmnDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetEhplmnDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->exception = std::make_shared<int>(100);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetFplmnDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetFplmnDone(event);

    event.reset();
    EXPECT_TRUE(simFile->ProcessGetHplmActDone(event) == true);
    simFile->ProcessGetEhplmnDone(event);
    simFile->ProcessGetFplmnDone(event);
    simFile->ProcessSetMbdn(event);
    simFile->ProcessMarkSms(event);
    simFile->ProcessObtainSpnPhase(event);
    simFile->ObtainExtensionElementaryFile(0);
    simFile->VoiceMailNotEditToSim();
    simFile->UpdateVoiceMail("", "");
    simFile->SetVoiceMailCount(3);
    auto cPtr = std::make_shared<unsigned char>(3);
    simFile->FillNumber(cPtr, 3, "123");
}

HWTEST_F(SimRilBranchTest2, Telephony_SimFile_Expand010, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    auto simFile = std::make_shared<SimFile>(simStateManager);
    simFile->fileController_ = std::make_shared<SimFileController>(1);
    simFile->telRilManager_ = telRilManager;
    simStateManager->Init(0);

    simFile->StartLoad();
    simFile->OnAllFilesFetched();
    simStateManager->simStateHandle_->externalType_ = CardType::SINGLE_MODE_USIM_CARD;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(0);
    simFile->ProcessIccReady(event);
    simFile->ProcessIccLocked(event);

    std::shared_ptr<IIccFileExt> iiccFileExt = std::make_shared<IIccFileExtImpl>();
    simFile->SetIccFile(iiccFileExt);
    simFile->spnStatus_ = SimFile::SpnStatus::OBTAIN_SPN_GENERAL;
    simFile->ObtainSpnPhase(true, event);
    simFile->ObtainSpnPhase(false, event);
    simFile->spnStatus_ = SimFile::SpnStatus::OBTAIN_SPN_START;
    simFile->ObtainSpnPhase(false, event);
    simFile->spnStatus_ = SimFile::SpnStatus::OBTAIN_OPERATOR_NAMESTRING;
    simFile->ObtainSpnPhase(false, event);
    simFile->spnStatus_ = SimFile::SpnStatus::OBTAIN_OPERATOR_NAME_SHORTFORM;
    simFile->ObtainSpnPhase(false, event);
    simFile->StartObtainSpn();
    TELEPHONY_EXT_WRAPPER.InitTelephonyExtWrapper();
    simFile->LoadSimFiles();
    TELEPHONY_EXT_WRAPPER.DeInitTelephonyExtWrapper();

    auto objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->resultData = "12345678";
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->spn_ = "";
    simFile->ProcessSpnGeneral(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->resultData = "12345678";
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->spn_ = "1234";
    simFile->ProcessSpnGeneral(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->spn_ = "1234";
    simFile->ProcessSpnCphs(event);
    EXPECT_TRUE(simFile->spnStatus_ == SimFile::SpnStatus::OBTAIN_SPN_NONE);
}

HWTEST_F(SimRilBranchTest2, Telephony_SimFile_Expand011, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    auto simFile = std::make_shared<SimFile>(simStateManager);
    simFile->fileController_ = std::make_shared<SimFileController>(1);

    simStateManager->Init(0);

    auto objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    auto event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->spn_ = "";
    simFile->ProcessSpnShortCphs(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->spn_ = "1234";
    simFile->ProcessSpnShortCphs(event);

    simFile->UpdateSimLanguage();

    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessObtainPlLanguage(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->resultData = "1234";
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessObtainPlLanguage(event);

    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->exception = std::make_shared<int>(100);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessObtainGid1Done(event);

    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessObtainGid2Done(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->exception = std::make_shared<int>(100);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessObtainGid2Done(event);

    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetCfisDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->resultData = "12345678";
    objectUnique->exception = std::make_shared<int>(100);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    EXPECT_TRUE(simFile->ProcessGetCfisDone(event) == true);
}

HWTEST_F(SimRilBranchTest2, Telephony_SimFile_Expand012, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    auto simFile = std::make_shared<SimFile>(simStateManager);
    simFile->fileController_ = std::make_shared<SimFileController>(1);
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(0);
    simFile->diallingNumberHandler_ = std::make_shared<IccDiallingNumbersHandler>(file);
    simStateManager->Init(0);

    auto objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    auto event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetMbiDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->resultData = "1234";
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetMwisDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->exception = std::make_shared<int>(100);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->iccId_ = "";
    simFile->reloadIccidCount_ = 1;
    simFile->ProcessGetIccIdDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->resultData = "1234";
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetPlmnActDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->resultData = "1234";
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetOplmnActDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->exception = std::make_shared<int>(100);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetCspCphs(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetCspCphs(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->resultData = "1234";
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetHplmActDone(event);

    simFile->GetCphsMailBox();

    event.reset();
    simFile->ProcessReloadIccid(event);
    EXPECT_TRUE(simFile->ProcessReloadImsi(event) == false);
}

HWTEST_F(SimRilBranchTest2, Telephony_SimFile_Expand013, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    auto simFile = std::make_shared<SimFile>(simStateManager);
    simFile->fileController_ = std::make_shared<SimFileController>(1);

    simStateManager->Init(0);

    auto objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->resultData = "1234";
    auto event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    simFile->ProcessGetEhplmnDone(event);
    objectUnique = std::make_unique<ControllerToFileMsg>(nullptr, nullptr);
    objectUnique->resultData = "1234";
    objectUnique->arg1 = ICC_CONTROLLER_REQ_SEND_RESPONSE;
    event = AppExecFwk::InnerEvent::Get(0, objectUnique);
    EXPECT_TRUE(simFile->ProcessGetFplmnDone(event) == false);

    simFile->OnParamChanged(nullptr, nullptr, nullptr);
    simFile->OnParamChanged("1234", nullptr, nullptr);
}
} // namespace Telephony
} // namespace OHOS
