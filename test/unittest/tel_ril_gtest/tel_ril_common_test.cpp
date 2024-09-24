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

#include "gtest/gtest.h"
#include "tel_event_handler.h"
#include "tel_ril_callback.h"
#include "tel_ril_handler.h"
#include "tel_ril_manager.h"
#include "sim_data_type.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

class TelRilCommonTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
void TelRilCommonTest::SetUpTestCase() {}

void TelRilCommonTest::TearDownTestCase() {}

void TelRilCommonTest::SetUp() {}

void TelRilCommonTest::TearDown() {}

/**
 * @tc.number   TelRilModem_BuildVoiceRadioTechnology_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilCommonTest, TelRilModem_BuildVoiceRadioTechnology_001, Function | MediumTest | Level1)
{
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilModem = std::make_shared<TelRilModem>(0, rilInterface, observerHandler, nullptr);
    HDI::Ril::V1_1::VoiceRadioTechnology voiceRadioTechnology;
    std::shared_ptr<VoiceRadioTechnology> mVoiceRadioTechnology = std::make_shared<VoiceRadioTechnology>();
    telRilModem->BuildVoiceRadioTechnology(voiceRadioTechnology, mVoiceRadioTechnology);
    ASSERT_TRUE(mVoiceRadioTechnology->actName == voiceRadioTechnology.actName);
}

/**
 * @tc.number   TelRilManager_ConnectRilInterface_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilCommonTest, TelRilManager_ConnectRilInterface_001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    telRilManager->rilInterface_ = nullptr;
    auto result = telRilManager->ConnectRilInterface();
    telRilManager->OnInit();
    telRilManager->ReduceRunningLock();
    ASSERT_EQ(result, true);
}

/**
 * @tc.number   TelRilManager_InitTelExtraModule_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilCommonTest, TelRilManager_InitTelExtraModule_001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    telRilManager->OnInit();
    auto result = telRilManager->InitTelExtraModule(0);
    ASSERT_EQ(result, TELEPHONY_ERROR);
    telRilManager->telRilCall_.clear();
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    for (int i = 0; i < SIM_SLOT_3; i++) {
        std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
        auto telRilCall = std::make_shared<TelRilCall>(i, rilInterface, observerHandler, telRilManager->handler_);
        telRilManager->telRilCall_.push_back(telRilCall);
    }
    result = telRilManager->InitTelExtraModule(SIM_SLOT_2);
    ASSERT_EQ(result, TELEPHONY_SUCCESS);
}

/**
 * @tc.number   TelRilManager_GetObserverHandler_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilCommonTest, TelRilManager_GetObserverHandler_001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    telRilManager->OnInit();
    auto result = telRilManager->GetObserverHandler(-1);
    ASSERT_EQ(result, nullptr);
    telRilManager->observerHandler_.clear();
    result = telRilManager->GetObserverHandler(SIM_SLOT_2);
    ASSERT_EQ(result, nullptr);
}

/**
 * @tc.number   TelRilSms_ConvertHexCharToInt_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilCommonTest, TelRilSms_ConvertHexCharToInt_001, Function | MediumTest | Level1)
{
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilSms = std::make_shared<TelRilSms>(0, rilInterface, observerHandler, nullptr);
    uint8_t ch = 'a';
    uint8_t expected = 10;
    uint8_t actual = telRilSms->ConvertHexCharToInt(ch);
    EXPECT_EQ(expected, actual);
}

/**
 * @tc.number   TelRilSms_ConvertHexCharToInt_002
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilCommonTest, TelRilSms_ConvertHexCharToInt_002, Function | MediumTest | Level1)
{
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilSms = std::make_shared<TelRilSms>(0, rilInterface, observerHandler, nullptr);
    uint8_t ch = 'A';
    uint8_t expected = 10;
    uint8_t actual = telRilSms->ConvertHexCharToInt(ch);
    EXPECT_EQ(expected, actual);
}

/**
 * @tc.number   TelRilSms_ConvertHexCharToInt_003
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilCommonTest, TelRilSms_ConvertHexCharToInt_003, Function | MediumTest | Level1)
{
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilSms = std::make_shared<TelRilSms>(0, rilInterface, observerHandler, nullptr);
    uint8_t ch = '5';
    uint8_t expected = 5;
    uint8_t actual = telRilSms->ConvertHexCharToInt(ch);
    EXPECT_EQ(expected, actual);
}

/**
 * @tc.number   TelRilSms_ConvertHexCharToInt_004
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilCommonTest, TelRilSms_ConvertHexCharToInt_004, Function | MediumTest | Level1)
{
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilSms = std::make_shared<TelRilSms>(0, rilInterface, observerHandler, nullptr);
    uint8_t ch = 'g';
    uint8_t expected = INVALID_HEX_CHAR;
    uint8_t actual = telRilSms->ConvertHexCharToInt(ch);
    EXPECT_EQ(expected, actual);
}

/**
 * @tc.number   TelRilSms_GetSmscAddrResponse_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilCommonTest, TelRilSms_GetSmscAddrResponse_001, Function | MediumTest | Level1)
{
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilSms = std::make_shared<TelRilSms>(0, rilInterface, observerHandler, nullptr);
    HDI::Ril::V1_1::RilRadioResponseInfo responseInfo;
    HDI::Ril::V1_1::ServiceCenterAddress serviceCenterAddress;
    int32_t result = telRilSms->GetSmscAddrResponse(responseInfo, serviceCenterAddress);
    ASSERT_NE(result, 1);
}

/**
 * @tc.number   TelRilSms_GetCBConfigResponse_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilCommonTest, TelRilSms_GetCBConfigResponse_001, Function | MediumTest | Level1)
{
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilSms = std::make_shared<TelRilSms>(0, rilInterface, observerHandler, nullptr);
    HDI::Ril::V1_1::RilRadioResponseInfo responseInfo;
    HDI::Ril::V1_1::CBConfigInfo cellBroadcastInfo;
    int32_t result = telRilSms->GetCBConfigResponse(responseInfo, cellBroadcastInfo);
    ASSERT_NE(result, 1);
}

/**
 * @tc.number   TelRilSms_GetCdmaCBConfigResponse_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilCommonTest, TelRilSms_GetCdmaCBConfigResponse_001, Function | MediumTest | Level1)
{
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilSms = std::make_shared<TelRilSms>(0, rilInterface, observerHandler, nullptr);
    HDI::Ril::V1_1::RilRadioResponseInfo responseInfo;
    HDI::Ril::V1_1::CdmaCBConfigInfo cdmaCBConfigInfo;
    int32_t result = telRilSms->GetCdmaCBConfigResponse(responseInfo, cdmaCBConfigInfo);
    ASSERT_NE(result, 1);
}

/**
 * @tc.number   TelRilSim_ErrorIccIoResponse_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilCommonTest, TelRilSim_ErrorIccIoResponse_001, Function | MediumTest | Level1)
{
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilSim = std::make_shared<TelRilSim>(0, rilInterface, observerHandler, nullptr);
    RadioResponseInfo responseInfo;
    auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_DIAL);
    auto telRilRequest = std::make_shared<TelRilRequest>(0, event);
    int32_t result = telRilSim->ErrorIccIoResponse(telRilRequest, responseInfo);
    ASSERT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> object = std::make_unique<Telephony::IccFromRilMsg>(holder);
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_DIAL, object);
    telRilRequest = std::make_shared<TelRilRequest>(0, event);
    result = telRilSim->ErrorIccIoResponse(telRilRequest, responseInfo);
    ASSERT_NE(result, TELEPHONY_ERR_SUCCESS);
    event = nullptr;
    telRilRequest = std::make_shared<TelRilRequest>(0, event);
    result = telRilSim->ErrorIccIoResponse(telRilRequest, responseInfo);
    ASSERT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

/**
 * @tc.number   TelRilSim_ProcessIccIoInfo_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilCommonTest, TelRilSim_ProcessIccIoInfo_001, Function | MediumTest | Level1)
{
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilSim = std::make_shared<TelRilSim>(0, rilInterface, observerHandler, nullptr);
    std::shared_ptr<IccIoResultInfo> iccIoResult = std::make_shared<IccIoResultInfo>();;
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> object = std::make_unique<Telephony::IccFromRilMsg>(holder);
    auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_DIAL, object);
    auto telRilRequest = std::make_shared<TelRilRequest>(0, event);
    int32_t result = telRilSim->ProcessIccIoInfo(telRilRequest, iccIoResult);
    ASSERT_NE(result, TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   TelRilSim_ProcessIccIoInfo_002
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilCommonTest, TelRilSim_ProcessIccIoInfo_002, Function | MediumTest | Level1)
{
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilSim = std::make_shared<TelRilSim>(0, rilInterface, observerHandler, nullptr);
    HDI::Ril::V1_1::IccIoResultInfo iccIoResultInfo;
    HDI::Ril::V1_1::RilRadioResponseInfo responseInfo;
    responseInfo.serial = 1;
    responseInfo.error = HDI::Ril::V1_1::RilErrType::NONE;
    auto event = AppExecFwk::InnerEvent::Get(1, 1);
    telRilSim->CreateTelRilRequest(event);
    auto result = telRilSim->ResponseIccIo(responseInfo, iccIoResultInfo);
    ASSERT_NE(result, TELEPHONY_ERR_SUCCESS);
    responseInfo.error = HDI::Ril::V1_1::RilErrType::RIL_ERR_GENERIC_FAILURE;
    event = AppExecFwk::InnerEvent::Get(1, 1);
    telRilSim->CreateTelRilRequest(event);
    telRilSim->ResponseIccIo(responseInfo, iccIoResultInfo);
    ASSERT_NE(result, 0);
}

/**
 * @tc.number   TelRilData_GetPdpContextListResponse_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilCommonTest, TelRilData_GetPdpContextListResponse_001, Function | MediumTest | Level1)
{
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilData = std::make_unique<TelRilData>(0, rilInterface, observerHandler, nullptr);
    HDI::Ril::V1_1::SetupDataCallResultInfo setupDataCallResultInfo;
    HDI::Ril::V1_1::DataCallResultList dataCallResultList;
    dataCallResultList.dcList.push_back(setupDataCallResultInfo);
    dataCallResultList.size = 1;
    HDI::Ril::V1_1::RilRadioResponseInfo responseInfo;
    auto result = telRilData->GetPdpContextListResponse(responseInfo, dataCallResultList);
    ASSERT_NE(result, TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   TelRilData_PdpContextListUpdated_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilCommonTest, TelRilData_PdpContextListUpdated_001, Function | MediumTest | Level1)
{
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilData = std::make_unique<TelRilData>(0, rilInterface, observerHandler, nullptr);
    HDI::Ril::V1_1::SetupDataCallResultInfo setupDataCallResultInfo;
    HDI::Ril::V1_1::DataCallResultList dataCallResultList;
    dataCallResultList.dcList.push_back(setupDataCallResultInfo);
    dataCallResultList.size = 1;
    auto result = telRilData->PdpContextListUpdated(dataCallResultList);
    ASSERT_EQ(result, TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   TelRilData_GetLinkBandwidthInfoResponse_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilCommonTest, TelRilData_GetLinkBandwidthInfoResponse_001, Function | MediumTest | Level1)
{
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilData = std::make_unique<TelRilData>(0, rilInterface, observerHandler, nullptr);
    HDI::Ril::V1_1::DataLinkBandwidthInfo dataLinkBandwidthInfo;
    HDI::Ril::V1_1::RilRadioResponseInfo responseInfo;
    auto result = telRilData->GetLinkBandwidthInfoResponse(responseInfo, dataLinkBandwidthInfo);
    ASSERT_NE(result, TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   TelRilCallback_CommonErrorResponse_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilCommonTest, TelRilCallback_CommonErrorResponse_001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto telRilCallback = std::make_shared<TelRilCallback>(telRilManager);
    HDI::Ril::V1_1::RilRadioResponseInfo responseInfo;
    EXPECT_EQ(telRilCallback->CommonErrorResponse(responseInfo), TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   TelRilCall_GetCallListResponse_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilCommonTest, TelRilCall_GetCallListResponse_001, Function | MediumTest | Level1)
{
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilCall = std::make_shared<TelRilCall>(0, rilInterface, observerHandler, nullptr);
    HDI::Ril::V1_1::RilRadioResponseInfo responseInfo;
    responseInfo.error = HDI::Ril::V1_1::RilErrType::RIL_ERR_GENERIC_FAILURE;
    HDI::Ril::V1_1::CallInfoList callInfoList;
    auto result = telRilCall->GetCallListResponse(responseInfo, callInfoList);
    EXPECT_EQ(result, TELEPHONY_ERR_ARGUMENT_INVALID);
}

/**
 * @tc.number   TelRilCall_GetCallWaitingResponse_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilCommonTest, TelRilCall_GetCallWaitingResponse_001, Function | MediumTest | Level1)
{
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilCall = std::make_shared<TelRilCall>(0, rilInterface, observerHandler, nullptr);
    HDI::Ril::V1_1::RilRadioResponseInfo responseInfo;
    responseInfo.error = HDI::Ril::V1_1::RilErrType::RIL_ERR_GENERIC_FAILURE;
    HDI::Ril::V1_1::CallWaitResult callWaitResult;
    auto result = telRilCall->GetCallWaitingResponse(responseInfo, callWaitResult);
    EXPECT_EQ(result, TELEPHONY_ERR_ARGUMENT_INVALID);
}

/**
 * @tc.number   TelRilCall_GetCallTransferInfoResponse_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilCommonTest, TelRilCall_GetCallTransferInfoResponse_001, Function | MediumTest | Level1)
{
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilCall = std::make_shared<TelRilCall>(0, rilInterface, observerHandler, nullptr);
    HDI::Ril::V1_1::RilRadioResponseInfo responseInfo;
    responseInfo.error = HDI::Ril::V1_1::RilErrType::RIL_ERR_GENERIC_FAILURE;
    HDI::Ril::V1_1::CallForwardQueryInfoList cFQueryList;
    auto result = telRilCall->GetCallTransferInfoResponse(responseInfo, cFQueryList);
    EXPECT_EQ(result, TELEPHONY_ERR_ARGUMENT_INVALID);
}

/**
 * @tc.number   TelRilCall_GetClipResponse_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilCommonTest, TelRilCall_GetClipResponse_001, Function | MediumTest | Level1)
{
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilCall = std::make_shared<TelRilCall>(0, rilInterface, observerHandler, nullptr);
    HDI::Ril::V1_1::RilRadioResponseInfo responseInfo;
    responseInfo.error = HDI::Ril::V1_1::RilErrType::RIL_ERR_GENERIC_FAILURE;
    HDI::Ril::V1_1::GetClipResult getClipResult;
    auto result = telRilCall->GetClipResponse(responseInfo, getClipResult);
    EXPECT_EQ(result, TELEPHONY_ERR_ARGUMENT_INVALID);
}

/**
 * @tc.number   TelRilCall_GetCallRestrictionResponse_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilCommonTest, TelRilCall_GetCallRestrictionResponse_001, Function | MediumTest | Level1)
{
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilCall = std::make_shared<TelRilCall>(0, rilInterface, observerHandler, nullptr);
    HDI::Ril::V1_1::RilRadioResponseInfo responseInfo;
    responseInfo.error = HDI::Ril::V1_1::RilErrType::RIL_ERR_GENERIC_FAILURE;
    HDI::Ril::V1_1::CallRestrictionResult callRestrictionResult;
    auto result = telRilCall->GetCallRestrictionResponse(responseInfo, callRestrictionResult);
    EXPECT_EQ(result, TELEPHONY_ERR_ARGUMENT_INVALID);
}

/**
 * @tc.number   TelRilSim_SendDtmfResponse_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilCommonTest, TelRilSim_SendDtmfResponse_001, Function | MediumTest | Level1)
{
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilCall = std::make_shared<TelRilCall>(0, rilInterface, observerHandler, nullptr);
    auto event = AppExecFwk::InnerEvent::Get(1, 1);
    telRilCall->CreateTelRilRequest(event);
    HDI::Ril::V1_1::RilRadioResponseInfo responseInfo;
    responseInfo.serial = 1;
    auto result = telRilCall->SendDtmfResponse(responseInfo);
    ASSERT_NE(result, 1);
    event = nullptr;
    telRilCall->CreateTelRilRequest(event);
    result = telRilCall->SendDtmfResponse(responseInfo);
    ASSERT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

/**
 * @tc.number   TelRilSim_CallUssdNotice_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilCommonTest, TelRilSim_CallUssdNotice_001, Function | MediumTest | Level1)
{
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilCall = std::make_shared<TelRilCall>(0, rilInterface, observerHandler, nullptr);
    HDI::Ril::V1_1::UssdNoticeInfo ussdNoticeInfo;
    auto result = telRilCall->CallUssdNotice(ussdNoticeInfo);
    ASSERT_NE(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

/**
 * @tc.number   TelRilSim_ResponseSupplement_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilCommonTest, TelRilSim_ResponseSupplement_001, Function | MediumTest | Level1)
{
    auto rilInterface = HDI::Ril::V1_3::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilCall = std::make_shared<TelRilCall>(0, rilInterface, observerHandler, nullptr);
    HDI::Ril::V1_1::RilRadioResponseInfo rilRadioResponseInfo;
    rilRadioResponseInfo.error = HDI::Ril::V1_1::RilErrType::RIL_ERR_GENERIC_FAILURE;
    auto result = telRilCall->ResponseSupplement(TELEPHONY_LOG_FUNC_NAME, rilRadioResponseInfo);
    ASSERT_NE(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

} // namespace Telephony
} // namespace OHOS