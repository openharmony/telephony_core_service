/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "tel_ril_test.h"

#include <fcntl.h>
#include <iostream>

#include "observer_handler.h"
#include "telephony_log_wrapper.h"

using namespace testing::ext;

namespace OHOS {
namespace Telephony {
const std::string GTEST_STRING = "1234";
const int32_t PW_LEN = 4;
const int32_t DECIMAL = 10;
const int32_t PHONE_NUM_LEN = 11;
const int32_t CID = 1;
const int32_t REASON = 2;
const int32_t P3 = 15;
const int32_t COMMAND = 192;
const int32_t FILEID = 20272;
const int32_t AUTHTYPE_1 = -1;

std::shared_ptr<Telephony::ITelRilManager> TelRilTest::telRilManager_ =
    CoreManager::GetInstance().getCore(CoreManager::DEFAULT_SLOT_ID)->GetRilManager();

void TelRilTest::SetUp() {}

void TelRilTest::TearDown() {}

void TelRilTest::SetUpTestCase()
{
    std::cout << "----------TelRilTest gtest start ------------" << std::endl;
}

void TelRilTest::TearDownTestCase()
{
    std::cout << "----------TelRilTest gtest end ------------" << std::endl;
}

TelRilTest::TelRilTest()
{
    AddRequestToMap();
}

TelRilTest::~TelRilTest()
{
    memberFuncMap_.clear();
}

void TelRilTest::ProcessTest(int32_t index, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    for (auto itFunc : memberFuncMap_) {
        int32_t val = static_cast<int32_t>(itFunc.first);
        if (val == index) {
            auto memberFunc = itFunc.second;
            (this->*memberFunc)(handler);
        }
    }
}

void TelRilTest::AddRequestToMap()
{
    InitCall();
    InitData();
    InitSim();
    InitSms();
    InitNetwork();
    InitModem();
}

void TelRilTest::InitCall()
{
    /* --------------------------------- CALL ----------------------------- */
    memberFuncMap_[DiffInterfaceId::TEST_CURRENT_CALLS] = &TelRilTest::CallGetCurrentCallsStatusTest;
    memberFuncMap_[DiffInterfaceId::TEST_CALL_DIAL] = &TelRilTest::CallDialTest;
    memberFuncMap_[DiffInterfaceId::TEST_HANDUP_CONNECT] = &TelRilTest::CallHangupTest;
    memberFuncMap_[DiffInterfaceId::TEST_ACCEPT_CALL] = &TelRilTest::CallAnswerTest;
    memberFuncMap_[DiffInterfaceId::TEST_HOLD_CALL] = &TelRilTest::CallHoldTest;
    memberFuncMap_[DiffInterfaceId::TEST_ACTIVE_CALL] = &TelRilTest::CallActiveTest;
    memberFuncMap_[DiffInterfaceId::TEST_SWAP_CALL] = &TelRilTest::CallSwapTest;
    memberFuncMap_[DiffInterfaceId::TEST_JOIN_CALL] = &TelRilTest::CallJoinTest;
    memberFuncMap_[DiffInterfaceId::TEST_SPLIT_CALL] = &TelRilTest::CallSplitTest;
    memberFuncMap_[DiffInterfaceId::TEST_REJECT_CALL] = &TelRilTest::RefusedCallTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_CALL_WAIT] = &TelRilTest::GetCallWaitTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_CALL_WAIT] = &TelRilTest::SetCallWaitTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_CALL_FORWARD] = &TelRilTest::GetCallForwardTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_CALL_FORWARD] = &TelRilTest::SetCallForwardTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_CALL_DEAL_CLIP] = &TelRilTest::GetClipTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_CALL_CLIP] = &TelRilTest::SetClipTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_CALL_RESTRICTION] = &TelRilTest::GetCallRestrictionTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_CALL_RESTRICTION] = &TelRilTest::SetCallRestrictionTest;
    memberFuncMap_[DiffInterfaceId::TEST_SEND_DTMF] = &TelRilTest::SendDtmfTest;
    memberFuncMap_[DiffInterfaceId::TEST_START_DTMF] = &TelRilTest::StartDtmfTest;
    memberFuncMap_[DiffInterfaceId::TEST_STOP_DTMF] = &TelRilTest::StopDtmfTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_USSD_CUSD] = &TelRilTest::SetUssdCusdTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_USSD_CUSD] = &TelRilTest::GetUssdCusdTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_CMUT] = &TelRilTest::SetMuteTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_CMUT] = &TelRilTest::GetMuteTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_EMERGENCY_CALL_LIST] = &TelRilTest::GetEmergencyCallListTest;
}

void TelRilTest::InitData()
{
    /* --------------------------------- DATA ----------------------------- */
    memberFuncMap_[DiffInterfaceId::TEST_RILCM_SET_INIT_APN_INFO] = &TelRilTest::DataSetInitApnInfoTest;
    memberFuncMap_[DiffInterfaceId::TEST_RILCM_SETUP_DATA_CALL] = &TelRilTest::DataSetupDataCallTest;
    memberFuncMap_[DiffInterfaceId::TEST_RILCM_DEACTIVATE_DATA_CALL] = &TelRilTest::DataDisableDataCallTest;
    memberFuncMap_[DiffInterfaceId::TEST_RILCM_GET_DATA_CALL_LIST] = &TelRilTest::GetDataCallListTest;
    memberFuncMap_[DiffInterfaceId::TEST_RILCM_GET_LINK_BANDWIDTH_INFO] = &TelRilTest::GetLinkBandwidthInfoTest;
    memberFuncMap_[DiffInterfaceId::TEST_RILCM_SET_LINK_BANDWIDTH_REPORTING_RULE] =
        &TelRilTest::OnRequestSetLinkBandwidthReportingRuleTest;
}

void TelRilTest::InitSim()
{
    /*-----------------------------------SIM----------------------------------*/
    memberFuncMap_[DiffInterfaceId::TEST_GET_SIM_CARD_STATUS] = &TelRilTest::SimGetSimStatusTest;
    memberFuncMap_[DiffInterfaceId::TEST_SIM_IO] = &TelRilTest::SimIccIoTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_IMSI] = &TelRilTest::SimGetImsiTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_SIM_LOCK_STATUS] = &TelRilTest::GetSimLockStatusTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_SIM_LOCK] = &TelRilTest::SetSimLockTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_CHANGE_SIM_PASSWD] = &TelRilTest::ChangeSimPasswordTest;
    memberFuncMap_[DiffInterfaceId::TEST_ENTER_SIM_PIN] = &TelRilTest::EnterSimPinTest;
    memberFuncMap_[DiffInterfaceId::TEST_UNLOCK_SIM_PIN] = &TelRilTest::UnlockSimPinTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_PIN_INPUT_TIMES] = &TelRilTest::GetSimPinInputTimesTest;
    memberFuncMap_[DiffInterfaceId::TEST_ENTER_SIM_PIN2] = &TelRilTest::EnterSimPin2Test;
    memberFuncMap_[DiffInterfaceId::TEST_UNLOCK_SIM_PIN2] = &TelRilTest::UnlockSimPin2Test;
    memberFuncMap_[DiffInterfaceId::TEST_GET_PIN2_INPUT_TIMES] = &TelRilTest::GetSimPin2InputTimesTest;
    memberFuncMap_[DiffInterfaceId::TEST_ENABLE_SIM_CARD] = &TelRilTest::EnableSimCardTest;
}

void TelRilTest::InitSms()
{
    /* --------------------------------- SMS ----------------------------- */
    memberFuncMap_[DiffInterfaceId::TEST_SEND_SMS] = &TelRilTest::SendRilCmSmsTest;
    memberFuncMap_[DiffInterfaceId::TEST_STORAGE_SMS] = &TelRilTest::StorageRilCmSmsTest;
    memberFuncMap_[DiffInterfaceId::TEST_DELETE_SMS] = &TelRilTest::DeleteRilCmSmsTest;
    memberFuncMap_[DiffInterfaceId::TEST_UPDATE_SMS] = &TelRilTest::UpdateRilCmSmsTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_SMS_CENTER_ADDRESS] = &TelRilTest::SetRilCmSmsCenterAddressTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_SMS_CENTER_ADDRESS] = &TelRilTest::GetRilCmSmsCenterAddressTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_CB_CONFIG] = &TelRilTest::SetRilCmCBConfigTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_CDMA_CB_CONFIG] =
        &TelRilTest::SetRilCmCdmaCBConfigTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_CB_CONFIG] = &TelRilTest::GetRilCmCBConfigTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_CDMA_CB_CONFIG] =
    &TelRilTest::GetRilCmCdmaCBConfigTest;
    memberFuncMap_[DiffInterfaceId::TEST_SEND_SMS_EXPECT_MORE] = &TelRilTest::SmsSendSmsExpectMoreTest;
    memberFuncMap_[DiffInterfaceId::TEST_SEND_SMS_ACK] = &TelRilTest::SmsAcknowledgeTest;
    memberFuncMap_[DiffInterfaceId::TEST_ADD_CDMA_SMS] = &TelRilTest::AddRilCmCdmaSmsTest;
    memberFuncMap_[DiffInterfaceId::TEST_DEL_CDMA_SMS] = &TelRilTest::DelRilCmCdmaSmsTest;
    memberFuncMap_[DiffInterfaceId::TEST_UPDATE_CDMA_SMS] = &TelRilTest::UpdateRilCmCdmaSmsTest;
}

void TelRilTest::InitNetwork()
{
    /* --------------------------------- NETWORK ----------------------------- */
    memberFuncMap_[DiffInterfaceId::TEST_OPERATOR] = &TelRilTest::NetworkOperatorTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_RILCM_VOICE_REGISTRATION_STATE] =
        &TelRilTest::NetworkVoiceRegistrationStateTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_RILCM_DATA_REGISTRATION_STATE] =
        &TelRilTest::NetworkDataRegistrationStateTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_NETWORKS_TO_USE] = &TelRilTest::GetNetworkSearchInformationTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_SELECTION_MOD_FOR_NETWORKS] =
        &TelRilTest::GetNetworkSelectionModeTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_MODE_AUTOMATIC_NETWORKS] =
        &TelRilTest::SetNetworkSelectionModeTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_PREFERRED_NETWORK_TYPE] =
        &TelRilTest::GetPreferredNetworkParaTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_PREFERRED_NETWORK_TYPE] =
        &TelRilTest::SetPreferredNetworkParaTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_IMEI] =
        &TelRilTest::GetImeiTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_MEID] =
        &TelRilTest::GetMeidTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_IMS_REG_STATUS] =
        &TelRilTest::GetImsRegStatusTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_PS_ATTACH_STATUS] =
        &TelRilTest::GetPsAttachStatusTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_PS_ATTACH_STATUS] =
        &TelRilTest::SetPsAttachStatusTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_RADIO_CAPABILITY] =
            &TelRilTest::GetRadioCapabilityTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_RADIO_CAPABILITY] =
            &TelRilTest::SetRadioCapabilityTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_VOICE_RADIO_INFO] =
        &TelRilTest::GetVoiceRadioTechnologyTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_PHYSICAL_CHANNEL_CONFIG] =
        &TelRilTest::GetPhysicalChannelConfigTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_LOCATE_UPDATES] =
        &TelRilTest::SetLocateUpdatesTest;
}

void TelRilTest::InitModem()
{
    /* --------------------------------- MODEM -------------------------- */
    memberFuncMap_[DiffInterfaceId::TEST_GET_SIGNAL_STRENGTH] = &TelRilTest::NetworkGetRssiTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_POWER_STATE] = &TelRilTest::SetRadioStateTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_POWER_STATE] = &TelRilTest::GetRadioStateTest;
}

void TelRilTest::CallGetCurrentCallsStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_CURRENT_CALLS);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::CallGetCurrentCallsStatusTest -->");
        telRilManager_->GetCallList(event);
        TELEPHONY_LOGI("TelRilTest::CallGetCurrentCallsStatusTest --> finished");
    }
}

/************************************** SIM test func *******************************************/
void TelRilTest::SimGetSimStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_GET_STATUS);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SimGetSimStatusTest -->");
        telRilManager_->GetSimStatus(event);
        TELEPHONY_LOGI("TelRilTest::SimGetSimStatusTest --> finished");
    }
}

void TelRilTest::SimIccIoTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_IO);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SimIccIoTest -->");
        SimIoRequestInfo msg;
        msg.command = COMMAND;
        msg.fileId = FILEID;
        msg.p1 = 0;
        msg.p2 = 0;
        msg.p3 = P3;
        msg.data = "";
        msg.path = "3F007F105F3A";
        msg.pin2 = "";
        telRilManager_->GetSimIO(msg, event);
        TELEPHONY_LOGI("TelRilTest::SimIccIoTest --> finished");
    }
}

void TelRilTest::SimGetImsiTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_GET_IMSI);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SimGetImsiTest -->");
        telRilManager_->GetImsi(event);
        TELEPHONY_LOGI("TelRilTest::SimGetImsiTest --> finished");
    }
}

void TelRilTest::GetSimLockStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_GET_LOCK_STATUS);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        std::string fac = GTEST_STRING;
        TELEPHONY_LOGI("TelRilTest::GetSimLockStatusTest -->");
        telRilManager_->GetSimLockStatus(fac, event);
        TELEPHONY_LOGI("TelRilTest::GetSimLockStatusTest --> finished");
    }
}

void TelRilTest::SetSimLockTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_SET_LOCK);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        std::string fac = GTEST_STRING;
        int mode = 0;
        std::string code = GTEST_STRING;
        TELEPHONY_LOGI("TelRilTest::SetSimLockTest -->");
        telRilManager_->SetSimLock(fac, mode, code, event);
        TELEPHONY_LOGI("TelRilTest::SetSimLockTest --> finished");
    }
}

void TelRilTest::ChangeSimPasswordTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_CHANGE_PASSWD);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        std::string fac = GTEST_STRING;
        std::string oldPassword = GTEST_STRING;
        std::string newPassword = GTEST_STRING;
        int32_t passwordLength = PW_LEN;
        TELEPHONY_LOGI("TelRilTest::ChangeSimPasswordTest -->");
        telRilManager_->ChangeSimPassword(fac, oldPassword, newPassword, passwordLength, event);
        TELEPHONY_LOGI("TelRilTest::ChangeSimPasswordTest --> finished");
    }
}

void TelRilTest::EnterSimPinTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_ENTER_PIN);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        std::string pin = GTEST_STRING;
        TELEPHONY_LOGI("TelRilTest::EnterSimPinTest -->");
        telRilManager_->UnlockPin(pin, event);
        TELEPHONY_LOGI("TelRilTest::EnterSimPinTest --> finished");
    }
}

void TelRilTest::UnlockSimPinTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_UNLOCK_PIN);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        std::string puk = GTEST_STRING;
        std::string pin = GTEST_STRING;
        TELEPHONY_LOGI("TelRilTest::UnlockSimPinTest -->");
        telRilManager_->UnlockPuk(puk, pin, event);
        TELEPHONY_LOGI("TelRilTest::UnlockSimPinTest --> finished");
    }
}

void TelRilTest::GetSimPinInputTimesTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_PIN_INPUT_TIMES);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetSimPinInputTimesTest -->");
        telRilManager_->GetSimPinInputTimes(event);
        TELEPHONY_LOGI("TelRilTest::GetSimPinInputTimesTest --> finished");
    }
}

void TelRilTest::EnterSimPin2Test(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_ENTER_PIN2);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        std::string pin2 = GTEST_STRING;
        TELEPHONY_LOGI("TelRilTest::EnterSimPin2Test -->");
        telRilManager_->UnlockPin2(pin2, event);
        TELEPHONY_LOGI("TelRilTest::EnterSimPin2Test --> finished");
    }
}

void TelRilTest::UnlockSimPin2Test(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_UNLOCK_PIN2);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        std::string puk2 = GTEST_STRING;
        std::string pin2 = GTEST_STRING;
        TELEPHONY_LOGI("TelRilTest::UnlockSimPin2Test -->");
        telRilManager_->UnlockPuk2(puk2, pin2, event);
        TELEPHONY_LOGI("TelRilTest::UnlockSimPin2Test --> finished");
    }
}

void TelRilTest::GetSimPin2InputTimesTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_PIN2_INPUT_TIMES);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetSimPin2InputTimesTest -->");
        telRilManager_->GetSimPin2InputTimes(event);
        TELEPHONY_LOGI("TelRilTest::GetSimPin2InputTimesTest --> finished");
    }
}

void TelRilTest::EnableSimCardTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_CARD_ENABLED);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        int index = 0;
        int enable = 0;
        TELEPHONY_LOGI("TelRilTest::EnableSimCardTest -->");
        telRilManager_->SetActiveSim(index, enable, event);
        TELEPHONY_LOGI("TelRilTest::EnableSimCardTest --> finished");
    }
}

/************************************** SIM test func *******************************************/

void TelRilTest::NetworkGetRssiTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_SIGNAL_STRENGTH);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::NetworkGetRssiTest -->");
        telRilManager_->GetSignalStrength(event);
        TELEPHONY_LOGI("TelRilTest::NetworkGetRssiTest --> finished");
    }
}

void TelRilTest::CallDialTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_DIAL);
    if (event == nullptr || telRilManager_ == nullptr) {
        TELEPHONY_LOGI("TelRilTest::CallDialTest failed!!!!");
        return;
    }

    std::string phoneNum = GetRandPhoneNum(PHONE_NUM_LEN);
    int32_t clirMode; /* Calling Line Identification Restriction . From TS 27.007 V3.4.0 (2000-03) */
    event->SetOwner(handler);
    clirMode = 0; // use subscription default value
    TELEPHONY_LOGI("TelRilTest::CallDialTest -->");
    telRilManager_->Dial(phoneNum, clirMode, event);
    TELEPHONY_LOGI("TelRilTest::CallDialTest --> finished");
}

void TelRilTest::RefusedCallTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_REJECT_CALL);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::RefusedCallTest -->");
        telRilManager_->Reject(event);
        TELEPHONY_LOGI("TelRilTest::RefusedCallTest --> finished");
    }
}

void TelRilTest::GetCallWaitTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_CALL_WAIT);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetCallWaitTest -->");
        telRilManager_->GetCallWaiting(event);
        TELEPHONY_LOGI("TelRilTest::GetCallWaitTest --> finished");
    }
}

void TelRilTest::SetCallWaitTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SET_CALL_WAIT);
    if (event == nullptr || telRilManager_ == nullptr)
        return;
    event->SetOwner(handler);
    int32_t operating = 0;
    TELEPHONY_LOGI("TelRilTest::SetCallWaitTest -->");
    telRilManager_->SetCallWaiting(operating, event);
    TELEPHONY_LOGI("TelRilTest::SetCallWaitTest --> finished");
}

void TelRilTest::CallHangupTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_HANGUP_CONNECT);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::CallHangupTest -->");
        telRilManager_->Hangup(static_cast<int>(event->GetInnerEventId()), event);
        TELEPHONY_LOGI("TelRilTest::CallHangupTest --> finished");
    }
}

void TelRilTest::CallAnswerTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_ACCEPT_CALL);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::CallAnswerTest -->");
        telRilManager_->Answer(event);
        TELEPHONY_LOGI("TelRilTest::CallAnswerTest --> finished");
    }
}

void TelRilTest::CallHoldTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_HOLD_CALL);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::CallHoldTest -->");
        telRilManager_->HoldCall(event);
        TELEPHONY_LOGI("TelRilTest::CallHoldTest --> finished");
    }
}

void TelRilTest::CallActiveTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_ACTIVE_CALL);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::CallActiveTest -->");
        telRilManager_->UnHoldCall(event);
        TELEPHONY_LOGI("TelRilTest::CallActiveTest --> finished");
    }
}

void TelRilTest::CallSwapTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SWAP_CALL);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::CallSwapTest -->");
        telRilManager_->SwitchCall(event);
        TELEPHONY_LOGI("TelRilTest::CallSwapTest --> finished");
    }
}

void TelRilTest::NetworkVoiceRegistrationStateTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_VOICE_REG_STATE);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::NetworkVoiceRegistrationStateTest -->");
        telRilManager_->GetCsRegStatus(event);
        TELEPHONY_LOGI("TelRilTest::NetworkVoiceRegistrationStateTest --> finished");
    }
}

void TelRilTest::NetworkDataRegistrationStateTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_DATA_REG_STATE);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::NetworkDataRegistrationStateTest -->");
        telRilManager_->GetPsRegStatus(event);
        TELEPHONY_LOGI("TelRilTest::NetworkDataRegistrationStateTest --> finished");
    }
}

void TelRilTest::NetworkOperatorTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_OPERATOR);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::NetworkOperatorTest -->");
        telRilManager_->GetOperatorInfo(event);
        TELEPHONY_LOGI("TelRilTest::NetworkOperatorTest --> finished");
    }
}

void TelRilTest::SendRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SEND_SMS);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SendRilCmSmsTest -->");
        telRilManager_->SendGsmSms("smscPdu", "pdu", event);
        TELEPHONY_LOGI("TelRilTest::SendRilCmSmsTest --> finished");
    }
}

void TelRilTest::StorageRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_STORAGE_SMS);
    int32_t status = 0;
    std::string smsc = GTEST_STRING;
    std::string pdu = GTEST_STRING;
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::StorageRilCmSmsTest -->");
        telRilManager_->AddSimMessage(status, smsc, pdu, event);
        TELEPHONY_LOGI("TelRilTest::StorageRilCmSmsTest --> finished");
    }
}

void TelRilTest::DeleteRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_DELETE_SMS);
    int32_t gsmIndex = 0;
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::DeleteRilCmSmsTest -->");
        telRilManager_->DelSimMessage(gsmIndex, event);
        TELEPHONY_LOGI("TelRilTest::DeleteRilCmSmsTest --> finished");
    }
}

void TelRilTest::UpdateRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_UPDATE_SMS);
    int32_t gsmIndex = 0;
    std::string pdu = GTEST_STRING;
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::UpdateRilCmSmsTest -->");
        telRilManager_->UpdateSimMessage(gsmIndex, 0, "00", pdu, event);
        TELEPHONY_LOGI("TelRilTest::UpdateRilCmSmsTest --> finished");
    }
}

void TelRilTest::SetRilCmSmsCenterAddressTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SET_SMS_CENTER_ADDRESS);
    int32_t tosca = 0;
    std::string address = GTEST_STRING;
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SetRilCmSmsCenterAddressTest -->");
        telRilManager_->SetSmscAddr(tosca, address, event);
        TELEPHONY_LOGI("TelRilTest::SetRilCmSmsCenterAddressTest --> finished");
    }
}

void TelRilTest::GetRilCmSmsCenterAddressTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_SMS_CENTER_ADDRESS);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetRilCmSmsCenterAddressTest -->");
        telRilManager_->GetSmscAddr(event);
        TELEPHONY_LOGI("TelRilTest::GetRilCmSmsCenterAddressTest --> finished");
    }
}

void TelRilTest::SetRilCmCBConfigTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SET_CELL_BROADCAST);
    int32_t mode = 0;
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SetRilCmCBConfigTest -->");
        telRilManager_->SetCBConfig(mode, "0,1,5,320-478,922", "0-3,5", event);
        TELEPHONY_LOGI("TelRilTest::SetRilCmCBConfigTest --> finished");
    }
}

void TelRilTest::SetRilCmCdmaCBConfigTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SET_CDMA_CELL_BROADCAST);
    CdmaCBConfigInfoList broadcastInfoList = {};
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SetRilCmCdmaCBConfigTest -->");
        telRilManager_->SetCdmaCBConfig(broadcastInfoList, event);
        TELEPHONY_LOGI("TelRilTest::SetRilCmCdmaCBConfigTest --> finished");
    }
}

void TelRilTest::GetRilCmCBConfigTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_CELL_BROADCAST);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetRilCmCBConfigTest -->");
        telRilManager_->GetCBConfig(event);
        TELEPHONY_LOGI("TelRilTest::GetRilCmCBConfigTest --> finished");
    }
}

void TelRilTest::GetRilCmCdmaCBConfigTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_CDMA_CELL_BROADCAST);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetRilCmCdmaCBConfigTest -->");
        telRilManager_->GetCdmaCBConfig(event);
        TELEPHONY_LOGI("TelRilTest::GetRilCmCdmaCBConfigTest --> finished");
    }
}

void TelRilTest::SmsSendSmsExpectMoreTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SEND_SMS_EXPECT_MORE);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SmsSendSmsExpectMoreTest -->");
        telRilManager_->SendSmsMoreMode("smscPdu", "pdu", event);
        TELEPHONY_LOGI("TelRilTest::SmsSendSmsExpectMoreTest --> finished");
    }
}

void TelRilTest::SetRadioStateTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SET_STATUS);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SetRadioStateTest -->");
        telRilManager_->SetRadioState(0, 0, event);
        TELEPHONY_LOGI("TelRilTest::SetRadioStateTest --> finished");
    }
}

void TelRilTest::GetRadioStateTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_STATUS);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetRadioStateTest -->");
        telRilManager_->GetRadioState(event);
        TELEPHONY_LOGI("TelRilTest::GetRadioStateTest --> finished");
    }
}

void TelRilTest::SmsAcknowledgeTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_SEND_SMS_ACK);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SmsAcknowledgeTest -->");
        telRilManager_->SendSmsAck(true, REASON, event);
        TELEPHONY_LOGI("TelRilTest::SmsAcknowledgeTest --> finished");
    }
}

void TelRilTest::AddRilCmCdmaSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_ADD_CDMA_SMS);
    int32_t status = 0;
    std::string pdu = GTEST_STRING;
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::AddRilCmCdmaSmsTest -->");
        telRilManager_->AddCdmaSimMessage(status, pdu, event);
        TELEPHONY_LOGI("TelRilTest::AddRilCmCdmaSmsTest --> finished");
    }
}

void TelRilTest::DelRilCmCdmaSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_DEL_CDMA_SMS);
    int32_t gsmIndex = 0;
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::DelRilCmCdmaSmsTest -->");
        telRilManager_->DelCdmaSimMessage(gsmIndex, event);
        TELEPHONY_LOGI("TelRilTest::DelRilCmCdmaSmsTest --> finished");
    }
}

void TelRilTest::UpdateRilCmCdmaSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_UPDATE_CDMA_SMS);
    int32_t cdmaIndex = 0;
    std::string pdu = GTEST_STRING;
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::UpdateRilCmCdmaSmsTest -->");
        telRilManager_->UpdateCdmaSimMessage(cdmaIndex, 0, pdu, event);
        TELEPHONY_LOGI("TelRilTest::UpdateRilCmCdmaSmsTest --> finished");
    }
}

void TelRilTest::DataSetInitApnInfoTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_SET_INIT_APN_INFO);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::DataSetInitApnInfoTest -->");
        ITelRilManager::CellularDataProfile dataProfile(0, "cmnet", "IPV4V6", AUTHTYPE_1, "", "", "IPV4V6");
        telRilManager_->SetInitApnInfo(dataProfile, event);
        TELEPHONY_LOGI("TelRilTest::DataSetInitApnInfoTest --> finished");
    }
}

void TelRilTest::DataSetupDataCallTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_SETUP_DATA_CALL);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::DataSetupDataCallTest -->");
        ITelRilManager::CellularDataProfile dataProfile(0, "cmnet", "IPV4V6", AUTHTYPE_1, "", "", "IPV4V6");
        telRilManager_->ActivatePdpContext(REASON, dataProfile, false, true, event);
        TELEPHONY_LOGI("TelRilTest::DataSetupDataCallTest --> finished");
    }
}

void TelRilTest::DataDisableDataCallTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_DEACTIVATE_DATA_CALL);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::DataDisableDataCallTest -->");
        telRilManager_->DeactivatePdpContext(CID, REASON, event);
        TELEPHONY_LOGI("TelRilTest::DataDisableDataCallTest --> finished");
    }
}

void TelRilTest::GetDataCallListTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_GET_DATA_CALL_LIST);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetDataCallListTest -->");
        telRilManager_->GetPdpContextList(event);
        TELEPHONY_LOGI("TelRilTest::GetDataCallListTest --> finished");
    }
}

void TelRilTest::GetNetworkSearchInformationTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_GET_NETWORKS_TO_USE);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetNetworkSearchInformationTest -->");
        telRilManager_->GetNetworkSearchInformation(event);
        TELEPHONY_LOGI("TelRilTest::GetNetworkSearchInformationTest --> finished");
    }
}

void TelRilTest::GetNetworkSelectionModeTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_GET_SELECTION_MOD_FOR_NETWORKS);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetNetworkSelectionModeTest -->");
        telRilManager_->GetNetworkSelectionMode(event);
        TELEPHONY_LOGI("TelRilTest::GetNetworkSelectionModeTest --> finished");
    }
}

void TelRilTest::SetNetworkSelectionModeTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_SET_MODE_AUTOMATIC_NETWORKS);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SetNetworkSelectionModeTest -->");
        telRilManager_->SetNetworkSelectionMode(0, "46001", event);
        TELEPHONY_LOGI("TelRilTest::SetNetworkSelectionModeTest --> finished");
    }
}

void TelRilTest::SetPreferredNetworkParaTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_SET_PREFERRED_NETWORK_TYPE);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        int32_t netType = 0;
        TELEPHONY_LOGI("TelRilTest::SetPreferredNetworkParaTest -->");
        telRilManager_->SetPreferredNetwork(netType, event);
        TELEPHONY_LOGI("TelRilTest::SetPreferredNetworkParaTest --> finished");
    }
}

void TelRilTest::GetPreferredNetworkParaTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_GET_PREFERRED_NETWORK_TYPE);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetPreferredNetworkParaTest -->");
        telRilManager_->GetPreferredNetwork(event);
        TELEPHONY_LOGI("TelRilTest::GetPreferredNetworkParaTest --> finished");
    }
}

void TelRilTest::GetImeiTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_GET_IMEI);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetImeiTest -->");
        telRilManager_->GetImei(event);
        TELEPHONY_LOGI("TelRilTest::GetImeiTest --> finished");
    }
}

void TelRilTest::GetMeidTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_GET_MEID);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetMeidTest -->");
        telRilManager_->GetMeid(event);
        TELEPHONY_LOGI("TelRilTest::GetMeidTest --> finished");
    }
}

void TelRilTest::GetImsRegStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_GET_IMS_REG_STATUS);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetImsRegStatusTest -->");
        telRilManager_->GetImsRegStatus(event);
        TELEPHONY_LOGI("TelRilTest::GetImsRegStatusTest --> finished");
    }
}

void TelRilTest::GetPsAttachStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_GET_PS_ATTACH_STATUS);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetPsAttachStatusTest -->");
        telRilManager_->GetPsAttachStatus(event);
        TELEPHONY_LOGI("TelRilTest::GetPsAttachStatusTest --> finished");
    }
}

void TelRilTest::SetPsAttachStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_SET_PS_ATTACH_STATUS);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        int32_t psAttachStatus = 0;
        TELEPHONY_LOGI("TelRilTest::SetPsAttachStatusTest -->psAttachStatus:%{public}d", psAttachStatus);
        telRilManager_->SetPsAttachStatus(psAttachStatus, event);
        TELEPHONY_LOGI("TelRilTest::SetPsAttachStatusTest --> finished");
    }
}

void TelRilTest::GetRadioCapabilityTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_GET_RADIO_CAPABILITY);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetRadioCapabilityTest -->");
        telRilManager_->GetRadioCapability(event);
        TELEPHONY_LOGI("TelRilTest::GetRadioCapabilityTest --> finished");
    }
}

void TelRilTest::SetRadioCapabilityTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_SET_RADIO_CAPABILITY);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    RadioCapabilityInfo radioCapabilityInfo = {};
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SetRadioCapabilityTest -->");
        telRilManager_->SetRadioCapability(radioCapabilityInfo, event);
        TELEPHONY_LOGI("TelRilTest::OnRequestSetRadioCapabilityTest --> SetRilCdmaCBConfigTest finished");
    }
}

void TelRilTest::GetVoiceRadioTechnologyTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_GET_VOICE_RADIO_INFO);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetVoiceRadioTechnologyTest -->");
        telRilManager_->GetVoiceRadioTechnology(event);
        TELEPHONY_LOGI("TelRilTest::GetVoiceRadioTechnologyTest --> finished");
    }
}

void TelRilTest::GetPhysicalChannelConfigTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_GET_PHYSICAL_CHANNEL_CONFIG);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetPhysicalChannelConfigTest -->");
        telRilManager_->GetPhysicalChannelConfig(event);
        TELEPHONY_LOGI("TelRilTest::GetPhysicalChannelConfigTest --> finished");
    }
}

void TelRilTest::SetLocateUpdatesTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_SET_LOCATE_UPDATES);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SetLocateUpdatesTest -->");
        HRilRegNotifyMode mode = REG_NOTIFY_STAT_LAC_CELLID;
        telRilManager_->SetLocateUpdates(mode, event);
        TELEPHONY_LOGI("TelRilTest::SetLocateUpdatesTest --> finished");
    }
}

void TelRilTest::CallJoinTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t callType = 0; /* call type
                           * 0: Voice call
                           * 1: Video call: send one-way video
                           * 2: Video call: two-way voice
                           * 3: Video call: two-way video, two-way voice
                           */
    TELEPHONY_LOGI("RilUnitTest::CallJoinTest -->");
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_JOIN_CALL);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::CallJoinTest -->");
        telRilManager_->CombineConference(callType, event);
        TELEPHONY_LOGI("TelRilTest::CallJoinTest --> finished");
    }
}

void TelRilTest::CallSplitTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t callIndex = 0;
    int32_t callType = 0; /* call type
                           * 0: Voice call
                           * 1: Video call: send one-way video
                           * 2: Video call:two-way voice
                           * 3: Video call: two-way video, two-way voice
                           */
    TELEPHONY_LOGI("RilUnitTest::CallSplitTest -->");
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SPLIT_CALL);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::CallSplitTest -->");
        telRilManager_->SeparateConference(callIndex, callType, event);
        TELEPHONY_LOGI("TelRilTest::CallSplitTest --> finished");
    }
}

void TelRilTest::GetCallForwardTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t reason = 0;
    TELEPHONY_LOGI("RilUnitTest::GetCallForwardTest -->");
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_CALL_FORWARD);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetCallForwardTest -->");
        telRilManager_->GetCallTransferInfo(reason, event);
        TELEPHONY_LOGI("TelRilTest::GetCallForwardTest --> finished");
    }
}

void TelRilTest::SetCallForwardTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t mode = 0;
    int32_t reasonType = 0;
    int32_t classx = 0; /* 0: Voice call
                         * 1: Video call: send one-way video
                         * 2: Video call: two-way voice
                         * 3: Video call: two-way video, two-way voice
                         */
    std::string phoneNum = GTEST_STRING;
    TELEPHONY_LOGI("RilUnitTest::SetCallForwardTest -->");
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SPLIT_CALL);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SetCallForwardTest -->");
        telRilManager_->SetCallTransferInfo(reasonType, mode, phoneNum, classx, event);
        TELEPHONY_LOGI("TelRilTest::SetCallForwardTest --> finished");
    }
}

void TelRilTest::GetClipTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_CALL_CLIP);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetClipTest -->");
        telRilManager_->GetClip(event);
        TELEPHONY_LOGI("TelRilTest::GetClipTest --> finished");
    }
}

void TelRilTest::SetClipTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SET_CALL_CLIP);
    if (event != nullptr && telRilManager_ != nullptr) {
        int32_t action = 0;
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SetClipTest -->");
        telRilManager_->SetClip(action, event);
        TELEPHONY_LOGI("TelRilTest::SetClipTest --> finished");
    }
}

void TelRilTest::GetCallRestrictionTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_CALL_RESTRICTION);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetCallRestrictionTest -->");
        telRilManager_->GetCallRestriction("AI", event);
        TELEPHONY_LOGI("TelRilTest::GetCallRestrictionTest --> finished");
    }
}

void TelRilTest::SetCallRestrictionTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SET_CALL_RESTRICTION);
    if (event != nullptr && telRilManager_ != nullptr) {
        int32_t mode = 0;
        std::string fac = GTEST_STRING;
        std::string password = GTEST_STRING;
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SetCallRestrictionTest -->");
        telRilManager_->SetCallRestriction(fac, mode, password, event);
        TELEPHONY_LOGI("TelRilTest::SetCallRestrictionTest --> finished");
    }
}

void TelRilTest::SendDtmfTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SEND_DTMF);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SendDtmfTest -->");
        TELEPHONY_LOGI("TelRilTest::SendDtmfTest --> finished");
    }
}

void TelRilTest::StartDtmfTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_START_DTMF);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::StartDtmfTest -->");
        TELEPHONY_LOGI("TelRilTest::StartDtmfTest --> finished");
    }
}

void TelRilTest::StopDtmfTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_STOP_DTMF);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::StopDtmfTest -->");
        TELEPHONY_LOGI("TelRilTest::StopDtmfTest --> finished");
    }
}

void TelRilTest::SetUssdCusdTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SET_USSD_CUSD);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SetUssdCusdTest -->");
        telRilManager_->SetUssdCusd("12345678", event);
        TELEPHONY_LOGI("TelRilTest::SetUssdCusdTest --> finished");
    }
}

void TelRilTest::GetUssdCusdTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_USSD_CUSD);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetUssdCusdTest -->");
        telRilManager_->GetUssdCusd(event);
        TELEPHONY_LOGI("TelRilTest::GetUssdCusdTest --> finished");
    }
}

void TelRilTest::SetMuteTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SET_CMUT);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SetMuteTest -->");
        telRilManager_->SetMute(1, event);
        TELEPHONY_LOGI("TelRilTest::setMuteTest --> finished");
    }
}

void TelRilTest::GetMuteTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_CMUT);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetCmutTest -->");
        telRilManager_->GetMute(event);
        TELEPHONY_LOGI("TelRilTest::GetCmutTest --> finished");
    }
}

void TelRilTest::GetEmergencyCallListTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_CMUT);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetEmergencyCallList -->");
        telRilManager_->GetEmergencyCallList(event);
        TELEPHONY_LOGI("TelRilTest::GetEmergencyCallList --> finished");
    }
}

void TelRilTest::OnRequestSetLinkBandwidthReportingRuleTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    const int BANDWITHD_HYSTERESIS_MS = 3000;
    const int BANDWITHD_HYSTERESIS_KBPS = 50;
    const int MAX_DOWNLINK_LINK_BANDWITHD[] = {
        100,    // VoIP
        500,    // Web
        1000,   // SD
        5000,   // HD
        10000,  // file
        20000,  // 4K
        50000,  // LTE
        100000,
        200000, // 5G
        500000,
        1000000
    };
    const int MAX_UPLINK_LINK_BANDWITHD[] = {
        100,
        500,
        1000,
        5000,
        10000,
        20000,
        50000,
        100000,
        200000
    };
    uint32_t i;
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_SET_LINK_BANDWIDTH_REPORTING_RULE);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestSetLinkBandwidthReportingRuleTest -->");
        LinkBandwidthRule rule;
        rule.delayMs = BANDWITHD_HYSTERESIS_MS;
        rule.rat = NETWORK_TYPE_LTE;
        rule.delayUplinkKbps = BANDWITHD_HYSTERESIS_KBPS;
        rule.delayDownlinkKbps = BANDWITHD_HYSTERESIS_KBPS;
        for (i = 0; i < sizeof(MAX_UPLINK_LINK_BANDWITHD) / sizeof(int); i++) {
            rule.maximumUplinkKbps.push_back(MAX_UPLINK_LINK_BANDWITHD[i]);
        }
        for (i = 0; i < sizeof(MAX_DOWNLINK_LINK_BANDWITHD) / sizeof(int); i++) {
            rule.maximumDownlinkKbps.push_back(MAX_DOWNLINK_LINK_BANDWITHD[i]);
        }
        telRilManager_->SetLinkBandwidthReportingRule(rule, event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestSetLinkBandwidthReportingRuleTest --> "
            "OnRequestSetLinkBandwidthReportingRuleTest finished");
    }
}

void TelRilTest::GetLinkBandwidthInfoTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_GET_LINK_BANDWIDTH_INFO);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        int32_t cid = CID;
        TELEPHONY_LOGI("TelRilTest::GetLinkBandwidthInfoTest -->");
        telRilManager_->GetLinkBandwidthInfo(cid, event);
        TELEPHONY_LOGI("TelRilTest::GetLinkBandwidthInfoTest --> finished");
    }
}

void TelRilTest::DemoHandler::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto eventId = event->GetInnerEventId();
    if (event != nullptr) {
        TELEPHONY_LOGI("TelRilTest::DemoHandler::ProcessEvent --> eventId:%{public}d", eventId);
    }
}

int32_t TelRilTest::GetRandNum()
{
    int32_t r = 0;
    int fd = open("/dev/random", O_RDONLY);
    if (fd > 0) {
        read(fd, &r, sizeof(int32_t));
    }
    close(fd);
    return r;
}

std::string TelRilTest::GetRandPhoneNum(const int len)
{
    char c;
    int32_t idx;
    int32_t rtv = 0;
    std::string str;

    for (idx = 0; idx < len; idx ++) {
        rtv = GetRandNum() % DECIMAL;
        c = static_cast<char>(rtv);
        str.push_back(c);
    }

    return str;
}

std::shared_ptr<TelRilTest::DemoHandler> TelRilTest::GetHandler(void)
{
    std::shared_ptr<AppExecFwk::EventRunner> eventRunner;
    std::shared_ptr<TelRilTest::DemoHandler> demohandler;
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("ERROR : make_shared<ITelRilManager>(telRilManager) --> nullptr !!!");
        return NULL;
    }
    TELEPHONY_LOGI("make_shared<ITelRilManager>(telRilManager) --> success");
    eventRunner = AppExecFwk::EventRunner::Create("DemoHandler");
    if (eventRunner == nullptr) {
        TELEPHONY_LOGE("ERROR : AppExecFwk::EventRunner::Create(\"DemoHandler\") --> nullptr !!!");
        return NULL;
    }
    TELEPHONY_LOGI("AppExecFwk::EventRunner::Create(\"DemoHandler\") --> success");
    demohandler = std::make_shared<TelRilTest::DemoHandler>(eventRunner);
    if (demohandler == nullptr) {
        TELEPHONY_LOGE("ERROR : make_shared<TelRilTest::DemoHandler>(runner) --> nullptr !!!");
        return NULL;
    }
    TELEPHONY_LOGI("make_shared<TelRilTest::DemoHandler>(runner) --> success");
    eventRunner->Run();

    return demohandler;
}

HWTEST_F(TelRilTest, Telephony_TelRil_NetworkGetRssiTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_SIGNAL_STRENGTH), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_SetRadioStateTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_POWER_STATE), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_GetRadioStateTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_POWER_STATE), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_DataSetInitApnInfoTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_SET_INIT_APN_INFO), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_DataSetupDataCallTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_SETUP_DATA_CALL), GetHandler());
}

HWTEST_F(TelRilTest, Telephony_TelRil_DataDisableDataCallTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_DEACTIVATE_DATA_CALL), GetHandler());
}

HWTEST_F(TelRilTest, Telephony_TelRil_GetDataCallListTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_GET_DATA_CALL_LIST), GetHandler());
}

HWTEST_F(TelRilTest, Telephony_TelRil_GetLinkBandwidthInfoTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_GET_LINK_BANDWIDTH_INFO), GetHandler());
}

HWTEST_F(TelRilTest, Telephony_TelRil_SetLinkBandwidthReportingRuleTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_SET_LINK_BANDWIDTH_REPORTING_RULE), GetHandler());
}

HWTEST_F(TelRilTest, Telephony_TelRil_CallGetCurrentCallsStatusTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_CURRENT_CALLS), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_CallDialTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_CALL_DIAL), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_CallHangupTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_HANDUP_CONNECT), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_CallAnswerTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ACCEPT_CALL), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_CallHoldTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_HOLD_CALL), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_CallActiveTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ACTIVE_CALL), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_CallSwapTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SWAP_CALL), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_CallJoinTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_JOIN_CALL), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_CallSplitTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SPLIT_CALL), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_RefusedCallTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_REJECT_CALL), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_GetCallWaitTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_CALL_WAIT), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_SetCallWaitTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_CALL_WAIT), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_GetCallForwardTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_CALL_FORWARD), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_SetCallForwardTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_CALL_FORWARD), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_GetClipTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_CALL_DEAL_CLIP), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_SetClipTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_CALL_CLIP), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_GetCallRestrictionTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_CALL_RESTRICTION), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_SetCallRestrictionTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_CALL_RESTRICTION), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_SendRilCmSmsTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SEND_SMS), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_StorageRilCmSmsTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_STORAGE_SMS), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_DeleteRilCmSmsTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_DELETE_SMS), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_UpdateRilCmSmsTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_UPDATE_SMS), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_SetRilCmSmsCenterAddressTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_SMS_CENTER_ADDRESS), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_GetRilCmSmsCenterAddressTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_SMS_CENTER_ADDRESS), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_SetRilCmCBConfigTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_CB_CONFIG), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_GetRilCmCBConfigTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_CB_CONFIG), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_GetRilCmCdmaCBConfigTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_CDMA_CB_CONFIG), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_SmsSendSmsExpectMoreTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SEND_SMS_EXPECT_MORE), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_SmsAcknowledgeTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SEND_SMS_ACK), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_AddRilCmCdmaSmsTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ADD_CDMA_SMS), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_DelRilCmCdmaSmsTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_DEL_CDMA_SMS), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_UpdateRilCmCdmaSmsTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_UPDATE_CDMA_SMS), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_SimGetSimStatusTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_SIM_CARD_STATUS), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_SimIccIoTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SIM_IO), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_SimGetImsiTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_IMSI), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_GetSimLockStatusTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_SIM_LOCK_STATUS), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_SetSimLockTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_SIM_LOCK), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_ChangeSimPasswordTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_CHANGE_SIM_PASSWD), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_EnterSimPinTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ENTER_SIM_PIN), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_UnlockSimPinTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_UNLOCK_SIM_PIN), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_GetSimPinInputTimesTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_PIN_INPUT_TIMES), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_EnterSimPin2Test_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ENTER_SIM_PIN2), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_UnlockSimPin2Test_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_UNLOCK_SIM_PIN2), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_GetSimPin2InputTimesTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_PIN2_INPUT_TIMES), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_EnableSimCardTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ENABLE_SIM_CARD), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_NetworkOperatorTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_OPERATOR), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_NetworkVoiceRegistrationStateTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_RILCM_VOICE_REGISTRATION_STATE), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_NetworkDataRegistrationStateTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_RILCM_DATA_REGISTRATION_STATE), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_GetNetworkSearchInformationTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_NETWORKS_TO_USE), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_GetNetworkSelectionModeTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_SELECTION_MOD_FOR_NETWORKS), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_SetNetworkSelectionModeTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_MODE_AUTOMATIC_NETWORKS), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_GetPreferredNetworkParaTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_PREFERRED_NETWORK_TYPE), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_SetPreferredNetworkParaTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_PREFERRED_NETWORK_TYPE), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_GetImeiTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_IMEI), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_GetMeidTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_MEID), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_GetImsRegStatusTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_IMS_REG_STATUS), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_GetPsAttachStatusTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_PS_ATTACH_STATUS), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_SetPsAttachStatusTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_PS_ATTACH_STATUS), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_GetRadioCapabilityTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_RADIO_CAPABILITY), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_SetRadioCapabilityTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_RADIO_CAPABILITY), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_GetVoiceRadioTechnologyTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_VOICE_RADIO_INFO), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_GetPhysicalChannelConfigTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_PHYSICAL_CHANNEL_CONFIG), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_SetLocateUpdatesTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_LOCATE_UPDATES), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_SetUssdCusdTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_USSD_CUSD), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_GetUssdCusdTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_USSD_CUSD), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_SetMuteTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_CMUT), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_GetMuteTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_CMUT), GetHandler());
    return;
}

HWTEST_F(TelRilTest, Telephony_TelRil_GetEmergencyCallListTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_EMERGENCY_CALL_LIST), GetHandler());
    return;
}
} // namespace Telephony
} // namespace OHOS