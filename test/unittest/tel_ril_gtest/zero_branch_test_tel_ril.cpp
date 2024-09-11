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

#include "event_runner.h"
#include "tel_ril_callback.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

namespace {
constexpr int32_t SLOT_ID = 0;
constexpr int32_t RAT_TYPE = 6;
} // namespace

class DemoHandler : public AppExecFwk::EventHandler {
public:
    explicit DemoHandler(std::shared_ptr<AppExecFwk::EventRunner> &runner) : AppExecFwk::EventHandler(runner) {}
    virtual ~DemoHandler() {}
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event) {}
};

class TelRilBranchTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
void TelRilBranchTest::SetUpTestCase() {}

void TelRilBranchTest::TearDownTestCase() {}

void TelRilBranchTest::SetUp() {}

void TelRilBranchTest::TearDown() {}

/**
 * @tc.number   Telephony_tel_ril_manager_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilBranchTest, Telephony_tel_ril_manager_001, Function | MediumTest | Level1)
{
    TELEPHONY_LOGI("Telephony_tel_ril_manager_001 entry");
    auto telRilManager = std::make_shared<TelRilManager>();
    telRilManager->OnInit();
    telRilManager->InitTelModule(SLOT_ID);
    telRilManager->ConnectRilInterface();
    telRilManager->DisConnectRilInterface();
    OHOS::HDI::ServiceManager::V1_0::ServiceStatus status;
    status.serviceName = "ril_service";
    status.deviceClass = DEVICE_CLASS_DEFAULT;
    status.status = SERVIE_STATUS_START;
    telRilManager->HandleRilInterfaceStatusCallback(status);
    status.status = SERVIE_STATUS_STOP;
    telRilManager->HandleRilInterfaceStatusCallback(status);

    std::shared_ptr<AppExecFwk::EventHandler> observerCallBack = nullptr;
    EXPECT_EQ(
        telRilManager->RegisterCoreNotify(SLOT_ID, observerCallBack, RadioEvent::RADIO_ICC_STATUS_CHANGED, nullptr),
        TELEPHONY_ERR_SUCCESS);
    telRilManager->GetTelRilModem(SLOT_ID)->RadioStateUpdated(ModemPowerState::CORE_SERVICE_POWER_ON);
    EXPECT_EQ(telRilManager->RegisterCoreNotify(SLOT_ID, observerCallBack, RadioEvent::RADIO_OFF, nullptr),
        TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(
        telRilManager->UnRegisterCoreNotify(SLOT_ID, observerCallBack, RadioEvent::RADIO_OFF), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(telRilManager->DeInit(), true);
}

/**
 * @tc.number   Telephony_tel_ril_Callback_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilBranchTest, Telephony_tel_ril_Callback_001, Function | MediumTest | Level1)
{
    TELEPHONY_LOGI("Telephony_tel_ril_Callback_001 entry");
    std::shared_ptr<TelRilManager> telRilManager = nullptr;
    auto telRilCallback = std::make_shared<TelRilCallback>(telRilManager);
    HDI::Ril::V1_1::RilRadioResponseInfo responseInfo;
    EXPECT_NE(telRilCallback->CommonErrorResponse(responseInfo), TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_tel_ril_Base_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilBranchTest, Telephony_tel_ril_Base_001, Function | MediumTest | Level1)
{
    TELEPHONY_LOGI("Telephony_tel_ril_Base_001 entry");
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilBase = std::make_shared<TelRilBase>(SLOT_ID, rilInterface, observerHandler, nullptr);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(1, 1);
    event = nullptr;
    telRilBase->GetSerialId(event);
    rilInterface = nullptr;
    telRilBase = std::make_shared<TelRilBase>(SLOT_ID, rilInterface, observerHandler, nullptr);
    telRilBase->GetSerialId(event);

    RadioResponseInfo responseInfo;
    std::shared_ptr<TelRilRequest> telRilRequest = nullptr;
    telRilBase->DfxWriteCallFaultEvent(telRilRequest, 1);
    EXPECT_NE(telRilBase->ErrorResponse(telRilRequest, responseInfo), TELEPHONY_ERR_SUCCESS);

    telRilRequest = std::make_shared<TelRilRequest>(0, event);
    telRilBase->DfxWriteCallFaultEvent(telRilRequest, 1);
    EXPECT_NE(telRilBase->ErrorResponse(telRilRequest, responseInfo), TELEPHONY_ERR_SUCCESS);

    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_DIAL);
    telRilRequest = std::make_shared<TelRilRequest>(0, event);
    telRilBase->DfxWriteCallFaultEvent(telRilRequest, 1);

    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_ACCEPT_CALL);
    telRilRequest = std::make_shared<TelRilRequest>(0, event);
    telRilBase->DfxWriteCallFaultEvent(telRilRequest, 1);

    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_REJECT_CALL);
    telRilRequest = std::make_shared<TelRilRequest>(0, event);
    telRilBase->DfxWriteCallFaultEvent(telRilRequest, 1);

    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_HANGUP_CONNECT);
    telRilRequest = std::make_shared<TelRilRequest>(0, event);
    telRilBase->DfxWriteCallFaultEvent(telRilRequest, 1);
}

/**
 * @tc.number   Telephony_tel_ril_Network_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilBranchTest, Telephony_tel_ril_Network_001, Function | MediumTest | Level1)
{
    TELEPHONY_LOGI("Telephony_tel_ril_Network_001 entry");
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilNetwork = std::make_shared<TelRilNetwork>(SLOT_ID, rilInterface, observerHandler, nullptr);

    CellNearbyInfo cellInfo;
    HDI::Ril::V1_1::CellNearbyInfo info;
    for (info.ratType = 0; info.ratType <= RAT_TYPE; info.ratType++) {
        telRilNetwork->FillCellNearbyInfo(cellInfo, info);
        EXPECT_EQ(cellInfo.ratType, info.ratType);
    }

    CellNearbyInfo cellInfo1;
    HDI::Ril::V1_2::CellNearbyInfo_1_2 info1;
    for (info.ratType = 0; info1.ratType <= RAT_TYPE; info1.ratType++) {
        telRilNetwork->FillCellNearbyInfo(cellInfo1, info1);
        EXPECT_EQ(cellInfo1.ratType, info1.ratType);
    }

    CurrentCellInfo currentCellInfo;
    HDI::Ril::V1_1::CurrentCellInfo CurrentInfo;
    for (info.ratType = 0; CurrentInfo.ratType <= RAT_TYPE; CurrentInfo.ratType++) {
        telRilNetwork->FillCurrentCellInfo(currentCellInfo, CurrentInfo);
        EXPECT_EQ(currentCellInfo.ratType, CurrentInfo.ratType);
    }

    CurrentCellInformation currentCellInformation;
    HDI::Ril::V1_1::CurrentCellInfo_1_1 currentInformation;
    for (info.ratType = 0; currentInformation.ratType <= RAT_TYPE; currentInformation.ratType++) {
        telRilNetwork->FillCurrentCellInformation(currentCellInformation, currentInformation);
        EXPECT_EQ(currentCellInformation.ratType, currentInformation.ratType);
    }

    CurrentCellInformation currentCellInformation1;
    HDI::Ril::V1_2::CurrentCellInfo_1_2 currentInformation1;
    for (info.ratType = 0; currentInformation1.ratType <= RAT_TYPE; currentInformation1.ratType++) {
        telRilNetwork->FillCurrentCellInformation(currentCellInformation1, currentInformation1);
        EXPECT_EQ(currentCellInformation1.ratType, currentInformation1.ratType);
    }
}

/**
 * @tc.number   Telephony_tel_ril_Sms_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilBranchTest, Telephony_tel_ril_Sms_001, Function | MediumTest | Level1)
{
    TELEPHONY_LOGI("Telephony_tel_ril_Sms_001 entry");
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilSms = std::make_shared<TelRilSms>(SLOT_ID, rilInterface, observerHandler, nullptr);

    uint8_t ch = 61;
    telRilSms->ConvertHexCharToInt(ch);
    ch = 41;
    telRilSms->ConvertHexCharToInt(ch);
    ch = 30;
    telRilSms->ConvertHexCharToInt(ch);
    ch = 39;
    telRilSms->ConvertHexCharToInt(ch);
    ch = 67;
    telRilSms->ConvertHexCharToInt(ch);

    uint8_t hexString = 1;
    size_t length = 1;
    telRilSms->ConvertHexStringToBytes(&hexString, length);

    hexString = 1;
    length = 0;
    telRilSms->ConvertHexStringToBytes(&hexString, length);

    hexString = 1;
    length = 2;
    telRilSms->ConvertHexStringToBytes(&hexString, length);

    HDI::Ril::V1_1::SmsMessageInfo iSmsMessageInfo;
    telRilSms->NewSmsNotify(iSmsMessageInfo);
    telRilSms->NewCdmaSmsNotify(iSmsMessageInfo);
    uint8_t *temp = (uint8_t *)"Sms";
    iSmsMessageInfo.pdu.push_back(*temp);
    telRilSms->NewCdmaSmsNotify(iSmsMessageInfo);
    telRilSms->SmsStatusReportNotify(iSmsMessageInfo);
    HDI::Ril::V1_1::CBConfigReportInfo iCellBroadConfigReportInfo;
    telRilSms->CBConfigNotify(iCellBroadConfigReportInfo);
}

/**
 * @tc.number   Telephony_observerhandler_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilBranchTest, Telephony_observerhandler_001, Function | MediumTest | Level1)
{
    TELEPHONY_LOGI("Telephony_observerhandler_001 entry");
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();

    int32_t what = 0;
    std::shared_ptr<AppExecFwk::EventRunner> eventRunner = AppExecFwk::EventRunner::Create("test");
    std::shared_ptr<DemoHandler> handler = std::make_shared<DemoHandler>(eventRunner);
    observerHandler->Remove(what, handler);
    observerHandler->RegObserver(what, handler);
    observerHandler->Remove(what, handler);

    for (what = 0; what < RAT_TYPE; what++) {
        observerHandler->RegObserver(what, handler);
    }
    observerHandler->Remove(what, handler);
    ASSERT_EQ(observerHandler->observerHandlerMap_.size(), 6);
}

/**
 * @tc.number   Telephony_tel_ril_Modem_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilBranchTest, Telephony_tel_ril_Modem_001, Function | MediumTest | Level1)
{
    TELEPHONY_LOGI("Telephony_tel_ril_Modem_001 entry");
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilModem = std::make_shared<TelRilModem>(SLOT_ID, rilInterface, observerHandler, nullptr);
    HDI::Ril::V1_1::VoiceRadioTechnology voiceRadioTechnology;
    std::shared_ptr<VoiceRadioTechnology> mVoiceRadioTechnology = nullptr;
    telRilModem->OnRilAdapterHostDied();
    telRilModem->BuildVoiceRadioTechnology(voiceRadioTechnology, mVoiceRadioTechnology);
    ASSERT_EQ(voiceRadioTechnology.actName, "");
}

/**
 * @tc.number   Telephony_tel_ril_Data_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilBranchTest, Telephony_tel_ril_Data_001, Function | MediumTest | Level1)
{
    TELEPHONY_LOGI("Telephony_tel_ril_Data_001 entry");
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilData = std::make_shared<TelRilData>(SLOT_ID, rilInterface, observerHandler, nullptr);
    HDI::Ril::V1_1::DataCallResultList iDataCallResultList;
    HDI::Ril::V1_1::DataLinkCapability dataLinkCapability;
    HDI::Ril::V1_1::RilRadioResponseInfo responseInfo;
    iDataCallResultList.size = 0xFF;
    EXPECT_NE(telRilData->GetPdpContextListResponse(responseInfo, iDataCallResultList), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(telRilData->PdpContextListUpdated(iDataCallResultList), TELEPHONY_ERR_SUCCESS);
    telRilData->DataLinkCapabilityUpdated(dataLinkCapability);
    telRilData->GetLinkCapabilityResponse(responseInfo, dataLinkCapability);
}

/**
 * @tc.number   Telephony_tel_ril_Sim_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilBranchTest, Telephony_tel_ril_Sim_001, Function | MediumTest | Level1)
{
    TELEPHONY_LOGI("Telephony_tel_ril_Sim_001 entry");
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilSim = std::make_shared<TelRilSim>(SLOT_ID, rilInterface, observerHandler, nullptr);

    std::shared_ptr<TelRilRequest> telRilRequest = nullptr;
    RadioResponseInfo responseInfo;
    std::shared_ptr<IccIoResultInfo> result = nullptr;
    EXPECT_NE(telRilSim->ErrorIccIoResponse(telRilRequest, responseInfo), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(telRilSim->ProcessIccIoInfo(telRilRequest, result), TELEPHONY_ERR_SUCCESS);

    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(1, 1);
    telRilRequest = std::make_shared<TelRilRequest>(0, event);
    EXPECT_NE(telRilSim->ProcessIccIoInfo(telRilRequest, result), TELEPHONY_ERR_SUCCESS);

    event = nullptr;
    telRilRequest = std::make_shared<TelRilRequest>(0, event);
    EXPECT_NE(telRilSim->ErrorIccIoResponse(telRilRequest, responseInfo), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(telRilSim->ProcessIccIoInfo(telRilRequest, result), TELEPHONY_ERR_SUCCESS);

    HDI::Ril::V1_1::RilRadioResponseInfo info;
    responseInfo.serial = -1;
    HDI::Ril::V1_1::IccIoResultInfo resultInfo;
    EXPECT_NE(telRilSim->ResponseIccIo(info, resultInfo), TELEPHONY_ERR_SUCCESS);

    responseInfo.serial = 1;
    telRilSim->CreateTelRilRequest(event);
    EXPECT_NE(telRilSim->ResponseIccIo(info, resultInfo), TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_tel_ril_Call_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilBranchTest, Telephony_tel_ril_Call_001, Function | MediumTest | Level1)
{
    TELEPHONY_LOGI("Telephony_tel_ril_Call_001 entry");
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilCall = std::make_shared<TelRilCall>(SLOT_ID, rilInterface, observerHandler, nullptr);

    HDI::Ril::V1_1::RilRadioResponseInfo responseInfo;
    HDI::Ril::V1_1::SsNoticeInfo ssNoticeInfo;
    HDI::Ril::V1_1::RingbackVoice ringbackVoice;
    HDI::Ril::V1_1::SrvccStatus srvccStatus;
    HDI::Ril::V1_1::GetClirResult getClirResult;

    telRilCall->CallSsNotice(ssNoticeInfo);
    telRilCall->CallRingbackVoiceNotice(ringbackVoice);
    telRilCall->CallSrvccStatusNotice(srvccStatus);
    responseInfo.error = HDI::Ril::V1_1::RilErrType::NONE;
    ASSERT_TRUE(telRilCall->ResponseSupplement(TELEPHONY_LOG_FUNC_NAME, responseInfo));
    telRilCall->ResponseSupplement(TELEPHONY_LOG_FUNC_NAME, responseInfo);
    responseInfo.error = HDI::Ril::V1_1::RilErrType::RIL_ERR_GENERIC_FAILURE;
    ASSERT_FALSE(telRilCall->ResponseSupplement(TELEPHONY_LOG_FUNC_NAME, responseInfo));
    telRilCall->ResponseSupplement(TELEPHONY_LOG_FUNC_NAME, responseInfo);
    telRilCall->GetClirResponse(responseInfo, getClirResult);

    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(1, 1);
    responseInfo.serial = -1;
    ASSERT_FALSE(telRilCall->SendDtmfResponse(responseInfo));

    responseInfo.serial = 1;
    telRilCall->CreateTelRilRequest(event);
    ASSERT_TRUE(telRilCall->SendDtmfResponse(responseInfo));

    event = nullptr;
    responseInfo.serial = 2;
    telRilCall->CreateTelRilRequest(event);
    ASSERT_TRUE(telRilCall->SendDtmfResponse(responseInfo));
}
} // namespace Telephony
} // namespace OHOS
