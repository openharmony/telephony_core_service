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

#include <iostream>

#include "core_manager.h"
#include "telephony_log_wrapper.h"

using namespace testing::ext;

namespace OHOS {
namespace Telephony {
enum class DiffInterfaceId {
    TEST_GET_RILCM_ICC_CARD_STATUS_TEST = 1,
    TEST_ICC_RILCM_IO_FOR_APP_TEST,
    TEST_GET_RILCM_IMSI_FOR_APP_TEST,
    TEST_GET_ICCID_TEST,
    TEST_GET_SIM_LOCK_STATUS_TEST,
    TEST_SET_SIM_LOCK_TEST,
    TEST_GET_CHANGE_SIM_PASSWD_TEST,
    TEST_ENTER_SIM_PIN_TEST,
    TEST_UNLOCK_SIM_PIN_TEST,
    TEST_GET_PIN_INPUT_TIMES_TEST,
    TEST_SET_RILCM_CELL_INFO_LIST_RATE_TEST,
    TEST_SET_RILCM_INITIAL_ATTACH_APN_TEST,
    TEST_SET_RILCM_DATA_PROFILE_TEST,
    TEST_GET_RILCM_VOICE_REGISTRATION_STATE_TEST,
    TEST_GET_RILCM_DATA_REGISTRATION_STATE_TEST,
    TEST_ACKNOWLEDGE_RILCM_LAST_INCOMING_GSM_SMS_TEST,
    TEST_SETUP_RILCM_DATA_CALL_TEST,

    TEST_DEACTIVATE_RILCM_DATA_CALL_TEST,
    TEST_SET_BASE_DATA_ALLOWED_TEST,
    TEST_GET_SIGNAL_STRENGTH,
    TEST_CALL_DIAL,
    TEST_HANDUP_CONNECT,
    TEST_ACCEPT_CALL,
    TEST_HOLD_CALL,
    TEST_ACTIVE_CALL,
    TEST_SWAP_CALL,
    TEST_JOIN_CALL,
    TEST_SPLIT_CALL,
    TEST_GET_CALL_WAIT,
    TEST_SET_CALL_WAIT,
    TEST_GET_CALL_FORWARD,
    TEST_SET_CALL_FORWARD,
    TEST_GET_CALL_DEAL_CLIP,
    TEST_SET_CALL_CLIP,
    TEST_GET_CALL_RESTRICTION,
    TEST_SET_CALL_RESTRICTION,
    TEST_SEND_DTMF,
    TEST_START_DTMF,
    TEST_STOP_DTMF,
    TEST_RADIO_LAST_CALL_FAIL_CAUSE,
    TEST_CURRENT_CALLS,
    TEST_REJECT_CALL,
    TEST_SEND_IMS_GSM_SMS,
    TEST_SEND_SMS,

    TEST_STORAGE_SMS,
    TEST_DELETE_SMS,
    TEST_UPDATE_SMS,
    TEST_SET_SMS_CENTER_ADDRESS,
    TEST_GET_SMS_CENTER_ADDRESS,
    TEST_SET_CELL_BROADCAST,
    TEST_SEND_SMS_EXPECT_MORE,
    TEST_SET_POWER_STATE,
    TEST_GET_POWER_STATE,
    TEST_OPERATOR,
    TEST_GET_NETWORKS_TO_USE,
    TEST_GET_SELECTION_MOD_FOR_NETWORKS,
    TEST_SET_MODE_AUTOMATIC_NETWORKS,
    TEST_SET_LOCATION_UPDATE_FOR_NETWORKS,
    TEST_GET_CURRENT_CELL_INFO,
    TEST_GET_CELL_INFO_LIST,
    TEST_EXIT,
};

const string GEEERIC_STRING = "1234";
const string GEEERIC_PHONENUM = "12345678923";
const int32_t LEN = 4;

static void GtestLog(const string logbuff)
{
    cout << "---" << logbuff << "---" << endl;
    TELEPHONY_LOGD("%{public}s", logbuff.c_str());
}

void TelRilTest::SetUpTestCase()
{
    GtestLog("TelRilTest gtest is start");
}

void TelRilTest::TearDownTestCase()
{
    GtestLog("TelRilTest gtest is end");
}

void TelRilTest::SetUp() {}

void TelRilTest::TearDown() {}

TelRilTest::TelRilTest()
{
    memberFuncMap_[TEST_CURRENT_CALLS] = &TelRilTest::OnRequestCallGetCurrentCallsStatusTest;
}

TelRilTest::~TelRilTest() {}

void TelRilTest::OnInitInterface()
{
    CoreManager::GetInstance().Init();
    rilManager_ = CoreManager::GetInstance().getCore(CoreManager::DEFAULT_SLOT_ID)->GetRilManager();
    /* --------------------------------- MODEL ----------------------------- */
    memberFuncMap_[TEST_GET_SIGNAL_STRENGTH] = &TelRilTest::OnRequestNetworkGetRssiTest;
    memberFuncMap_[TEST_SET_POWER_STATE] = &TelRilTest::OnRequestSetRadioStatusTest;
    memberFuncMap_[TEST_GET_POWER_STATE] = &TelRilTest::OnRequestGetRadioStatusTest;
    /* --------------------------------- DATA ----------------------------- */
    memberFuncMap_[TEST_DEACTIVATE_RILCM_DATA_CALL_TEST] = &TelRilTest::OnRequestDataDisableDataCallTest;
    OnInitCall();
    OnInitSms();
    OnInitSim();
    OnInitNetwork();
}

void TelRilTest::OnInitCall()
{
    /* --------------------------------- CALL ----------------------------- */
    memberFuncMap_[TEST_CALL_DIAL] = &TelRilTest::OnRequestCallDialTest;
    memberFuncMap_[TEST_HANDUP_CONNECT] = &TelRilTest::OnRequestCallHangupTest;
    memberFuncMap_[TEST_ACCEPT_CALL] = &TelRilTest::OnRequestCallAnswerTest;
    memberFuncMap_[TEST_HOLD_CALL] = &TelRilTest::OnRequestCallHoldTest;
    memberFuncMap_[TEST_ACTIVE_CALL] = &TelRilTest::OnRequestCallActiveTest;
    memberFuncMap_[TEST_SWAP_CALL] = &TelRilTest::OnRequestCallSwapTest;
    memberFuncMap_[TEST_JOIN_CALL] = &TelRilTest::OnRequestCallJoinTest;
    memberFuncMap_[TEST_SPLIT_CALL] = &TelRilTest::OnRequestCallSplitTest;
    memberFuncMap_[TEST_REJECT_CALL] = &TelRilTest::OnRequestRefusedCallTest;
    memberFuncMap_[TEST_GET_CALL_WAIT] = &TelRilTest::OnRequestGetCallWaitTest;
    memberFuncMap_[TEST_SET_CALL_WAIT] = &TelRilTest::OnRequestSetCallWaitTest;
    memberFuncMap_[TEST_GET_CALL_FORWARD] = &TelRilTest::OnRequestGetCallForwardTest;
    memberFuncMap_[TEST_SET_CALL_FORWARD] = &TelRilTest::OnRequestSetCallForwardTest;
    memberFuncMap_[TEST_GET_CALL_DEAL_CLIP] = &TelRilTest::OnRequestGetClipTest;
    memberFuncMap_[TEST_SET_CALL_CLIP] = &TelRilTest::OnRequestSetClipTest;
    memberFuncMap_[TEST_GET_CALL_RESTRICTION] = &TelRilTest::OnRequestGetCallRestrictionTest;
    memberFuncMap_[TEST_SET_CALL_RESTRICTION] = &TelRilTest::OnRequestSetCallRestrictionTest;
    memberFuncMap_[TEST_SEND_DTMF] = &TelRilTest::OnRequestSendDtmfTest;
    memberFuncMap_[TEST_START_DTMF] = &TelRilTest::OnRequestStartDtmfTest;
    memberFuncMap_[TEST_STOP_DTMF] = &TelRilTest::OnRequestStopDtmfTest;
}

void TelRilTest::OnInitSms()
{
    /* --------------------------------- SMS ----------------------------- */
    memberFuncMap_[TEST_SEND_SMS] = &TelRilTest::OnRequestSendRilCmSmsTest;
    memberFuncMap_[TEST_STORAGE_SMS] = &TelRilTest::OnRequestStorageRilCmSmsTest;
    memberFuncMap_[TEST_DELETE_SMS] = &TelRilTest::OnRequestDeleteRilCmSmsTest;
    memberFuncMap_[TEST_UPDATE_SMS] = &TelRilTest::OnRequestUpdateRilCmSmsTest;
    memberFuncMap_[TEST_SET_SMS_CENTER_ADDRESS] = &TelRilTest::OnRequestSetRilCmSmsCenterAddressTest;
    memberFuncMap_[TEST_GET_SMS_CENTER_ADDRESS] = &TelRilTest::OnRequestGetRilCmSmsCenterAddressTest;
    memberFuncMap_[TEST_SET_CELL_BROADCAST] = &TelRilTest::OnRequestSetRilCmCellBroadcastTest;
    memberFuncMap_[TEST_SEND_SMS_EXPECT_MORE] = &TelRilTest::OnRequestSmsSendSmsExpectMoreTest;
    memberFuncMap_[TEST_ACKNOWLEDGE_RILCM_LAST_INCOMING_GSM_SMS_TEST] = &TelRilTest::OnRequestSmsAcknowledgeTest;
}

void TelRilTest::OnInitSim()
{
    /*-----------------------------------SIM----------------------------------*/
    memberFuncMap_[TEST_GET_RILCM_ICC_CARD_STATUS_TEST] = &TelRilTest::OnRequestSimGetSimStatusTest;
    memberFuncMap_[TEST_ICC_RILCM_IO_FOR_APP_TEST] = &TelRilTest::OnRequestSimIccIoTest;
    memberFuncMap_[TEST_GET_RILCM_IMSI_FOR_APP_TEST] = &TelRilTest::OnRequestSimGetImsiTest;
    memberFuncMap_[TEST_GET_ICCID_TEST] = &TelRilTest::OnRequestSimGetIccIDTest;
    memberFuncMap_[TEST_GET_SIM_LOCK_STATUS_TEST] = &TelRilTest::OnRequestGetSimLockStatusTest;
    memberFuncMap_[TEST_SET_SIM_LOCK_TEST] = &TelRilTest::OnRequestSetSimLockTest;
    memberFuncMap_[TEST_GET_CHANGE_SIM_PASSWD_TEST] = &TelRilTest::OnRequestChangeSimPasswordTest;
    memberFuncMap_[TEST_UNLOCK_SIM_PIN_TEST] = &TelRilTest::OnRequestUnlockSimPinTest;
    memberFuncMap_[TEST_GET_PIN_INPUT_TIMES_TEST] = &TelRilTest::OnRequestGetSimPinInputTimesTest;
}

void TelRilTest::OnInitNetwork()
{
    /* --------------------------------- NETWORK ----------------------------- */
    memberFuncMap_[TEST_OPERATOR] = &TelRilTest::OnRequestNetworkOperatorTest;
    memberFuncMap_[TEST_GET_RILCM_VOICE_REGISTRATION_STATE_TEST] =
        &TelRilTest::OnRequestNetworkVoiceRegistrationStateTest;
    memberFuncMap_[TEST_GET_RILCM_DATA_REGISTRATION_STATE_TEST] =
        &TelRilTest::OnRequestNetworkDataRegistrationStateTest;
    memberFuncMap_[TEST_GET_NETWORKS_TO_USE] = &TelRilTest::OnRequestGetNetworkSearchInformationTest;
    memberFuncMap_[TEST_GET_SELECTION_MOD_FOR_NETWORKS] = &TelRilTest::OnRequestGetNetworkSelectionModeTest;
    memberFuncMap_[TEST_SET_MODE_AUTOMATIC_NETWORKS] = &TelRilTest::OnRequestSetNetworkSelectionModeTest;
    memberFuncMap_[TEST_SET_LOCATION_UPDATE_FOR_NETWORKS] = &TelRilTest::OnRequestSetNetworkLocationUpdateTest;
}

void TelRilTest::OnInitForRegister(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    // Register all APIs
    rilManager_->RegisterPhoneNotify(handler, ObserverHandler::RADIO_STATE_CHANGED, nullptr);
    rilManager_->RegisterPhoneNotify(handler, ObserverHandler::RADIO_IMS_NETWORK_STATE_CHANGED, nullptr);
    rilManager_->RegisterPhoneNotify(handler, ObserverHandler::RADIO_ON, nullptr);
    rilManager_->RegisterPhoneNotify(handler, ObserverHandler::RADIO_NOT_AVAIL, nullptr);
    rilManager_->RegisterPhoneNotify(handler, ObserverHandler::RADIO_CALL_STATE, nullptr);
    rilManager_->RegisterPhoneNotify(handler, ObserverHandler::RADIO_NETWORK_STATE, nullptr);
    rilManager_->RegisterPhoneNotify(handler, ObserverHandler::RADIO_DATA_CALL_LIST_CHANGED, nullptr);
    rilManager_->RegisterPhoneNotify(handler, ObserverHandler::RADIO_ICC_STATUS_CHANGED, nullptr);
    rilManager_->RegisterPhoneNotify(handler, ObserverHandler::RADIO_GSM_SMS, nullptr);
    rilManager_->RegisterPhoneNotify(handler, ObserverHandler::RADIO_SMS_ON_SIM, nullptr);
    rilManager_->RegisterPhoneNotify(handler, ObserverHandler::RADIO_SMS_STATUS, nullptr);
    rilManager_->RegisterPhoneNotify(handler, ObserverHandler::RADIO_SIGNAL_STRENGTH_UPDATE, nullptr);
    rilManager_->RegisterPhoneNotify(handler, ObserverHandler::RADIO_ICC_REFRESH, nullptr);
    rilManager_->RegisterPhoneNotify(handler, ObserverHandler::RADIO_CONNECTED, nullptr);
    rilManager_->RegisterPhoneNotify(handler, ObserverHandler::RADIO_PCODATA, nullptr);
    rilManager_->RegisterPhoneNotify(handler, ObserverHandler::RADIO_JOIN_CALL, nullptr);
    rilManager_->RegisterPhoneNotify(handler, ObserverHandler::RADIO_SPLIT_CALL, nullptr);
    rilManager_->RegisterPhoneNotify(handler, ObserverHandler::RADIO_GET_CALL_WAIT, nullptr);
    rilManager_->RegisterPhoneNotify(handler, ObserverHandler::RADIO_SET_CALL_WAIT, nullptr);
    rilManager_->RegisterPhoneNotify(handler, ObserverHandler::RADIO_GET_CALL_FORWARD, nullptr);
    rilManager_->RegisterPhoneNotify(handler, ObserverHandler::RADIO_SET_CALL_FORWARD, nullptr);
    rilManager_->RegisterPhoneNotify(handler, ObserverHandler::RADIO_GET_CALL_CLIP, nullptr);
    rilManager_->RegisterPhoneNotify(handler, ObserverHandler::RADIO_SET_CALL_CLIP, nullptr);
    rilManager_->RegisterPhoneNotify(handler, ObserverHandler::RADIO_GET_CALL_RESTRICTION, nullptr);
    rilManager_->RegisterPhoneNotify(handler, ObserverHandler::RADIO_SET_CALL_RESTRICTION, nullptr);
    rilManager_->RegisterPhoneNotify(handler, ObserverHandler::RADIO_SEND_DTMF, nullptr);
    rilManager_->RegisterPhoneNotify(handler, ObserverHandler::RADIO_START_DTMF, nullptr);
    rilManager_->RegisterPhoneNotify(handler, ObserverHandler::RADIO_STOP_DTMF, nullptr);
    rilManager_->RegisterPhoneNotify(handler, ObserverHandler::RADIO_REJECT_CALL, nullptr);
}

void TelRilTest::OnProcessTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    for (auto itFunc : memberFuncMap_) {
        auto memberFunc = itFunc.second;
        if (memberFunc != nullptr) {
            (this->*memberFunc)(handler);
        }
    }
}

void TelRilTest::OnRequestCallGetCurrentCallsStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_CURRENT_CALLS);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestCallGetCurrentCallsStatusTest -->");
        rilManager_->GetCallList(event);
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestCallGetCurrentCallsStatusTest --> "
            "OnRequestCallGetCurrentCallsStatusTest "
            "finished");
    }
}
/************************************** SIM test func *******************************************/
void TelRilTest::OnRequestSimGetSimStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_GET_STATUS);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestSimGetSimStatusTest -->");
        rilManager_->GetSimStatus(event);
        TELEPHONY_LOGD("TelRilTest::OnRequestSimGetSimStatusTest --> OnRequestSimGetSimStatusTest finished");
    }
}

void TelRilTest::OnRequestSimIccIoTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_IO);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestSimIccIoTest -->");
        rilManager_->RequestSimIO(COMMAND, FILEID, 0, 0, P3, "", "3F007F105F3A", event);
        TELEPHONY_LOGD("TelRilTest::OnRequestSimIccIoTest --> OnRequestSimIccIoTest finished");
    }
}

void TelRilTest::OnRequestSimGetImsiTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_GET_IMSI);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestSimGetImsiTest -->");
        rilManager_->GetImsi(event);
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestSimGetImsiTest --> "
            "OnRequestSimGetImsiTest finished");
    }
}

void TelRilTest::OnRequestSimGetIccIDTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_GET_ICCID);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::%{public}s -->", __func__);
        rilManager_->GetIccID(event);
        TELEPHONY_LOGD("TelRilTest::%{public}s --> finished", __func__);
    }
}

void TelRilTest::OnRequestGetSimLockStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_GET_LOCK_STATUS);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        std::string fac = GEEERIC_STRING;
        TELEPHONY_LOGD("TelRilTest::%{public}s -->", __func__);
        rilManager_->GetSimLockStatus(fac, event);
        TELEPHONY_LOGD("TelRilTest::%{public}s --> finished", __func__);
    }
}

void TelRilTest::OnRequestSetSimLockTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_SET_LOCK);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        std::string fac = GEEERIC_STRING;
        int mode = 0;
        std::string code = GEEERIC_STRING;
        TELEPHONY_LOGD("TelRilTest::%{public}s -->", __func__);
        rilManager_->SetSimLock(fac, mode, code, event);
        TELEPHONY_LOGD("TelRilTest::%{public}s --> finished", __func__);
    }
}

void TelRilTest::OnRequestChangeSimPasswordTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_CHANGE_PASSWD);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        std::string fac = GEEERIC_STRING;
        std::string oldPassword = GEEERIC_STRING;
        std::string newPassword = GEEERIC_STRING;
        int32_t passwordLength = LEN;
        rilManager_->ChangeSimPassword(fac, oldPassword, newPassword, passwordLength, event);
        TELEPHONY_LOGD("TelRilTest::%{public}s --> finished", __func__);
    }
}

void TelRilTest::OnRequestUnlockSimPinTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_UNLOCK_PIN);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        std::string puk = GEEERIC_STRING;
        std::string pin = GEEERIC_STRING;
        TELEPHONY_LOGD("TelRilTest::%{public}s -->", __func__);
        rilManager_->UnlockSimPin(puk, pin, event);
        TELEPHONY_LOGD("TelRilTest::%{public}s --> finished", __func__);
    }
}

void TelRilTest::OnRequestGetSimPinInputTimesTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_PIN_INPUT_TIMES);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::%{public}s -->", __func__);
        rilManager_->GetSimPinInputTimes(event);
        TELEPHONY_LOGD("TelRilTest::%{public}s --> finished", __func__);
    }
}

/************************************** SIM test func *******************************************/

void TelRilTest::OnRequestNetworkGetRssiTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_SIGNAL_STRENGTH);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestNetworkGetRssiTest -->");
        rilManager_->GetSignalStrength(event);
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestNetworkGetRssiTest --> "
            "OnRequestNetworkGetRssiTest finished");
    }
}

void TelRilTest::OnRequestCallDialTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_DIAL);
    if (event == nullptr || rilManager_ == nullptr) {
        TELEPHONY_LOGD("TelRilTest::OnRequestCallDialTest failed!!!!");
        return;
    }
    int32_t clirMode = 0; /* Calling Line Identification Restriction . From TS 27.007 V3.4.0 (2000-03) */
    event->SetOwner(handler);
    clirMode = 0; // use subscription default value
    TELEPHONY_LOGD("TelRilTest::OnRequestCallDialTest -->");
    rilManager_->Dial(GEEERIC_PHONENUM, clirMode, event);
    TELEPHONY_LOGD(
        "TelRilTest::OnRequestCallDialTest --> "
        "OnRequestCallDialTest finished");
}

void TelRilTest::OnRequestRefusedCallTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_REJECT_CALL);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestRefusedCallTest -->");
        rilManager_->Reject(event);
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestRefusedCallTest --> "
            "OnRequestRefusedCallTest finished");
    }
}

void TelRilTest::OnRequestGetCallWaitTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_CALL_WAIT);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestGetCallWaitTest -->");
        rilManager_->GetCallWait(event);
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestGetCallWaitTest --> "
            "OnRequestGetCallWaitTest finished");
    }
}

void TelRilTest::OnRequestSetCallWaitTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SET_CALL_WAIT);
    if (event == nullptr || rilManager_ == nullptr)
        return;
    event->SetOwner(handler);
    int32_t operating = 0;
    TELEPHONY_LOGD("TelRilTest::OnRequestSetCallWaitTest -->");
    rilManager_->SetCallWait(operating, event);
    TELEPHONY_LOGD(
        "TelRilTest::OnRequestSetCallWaitTest --> "
        "OnRequestSetCallWaitTest finished");
}

void TelRilTest::OnRequestCallHangupTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_HANGUP_CONNECT);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestCallHangupTest -->");
        rilManager_->Hangup(static_cast<int>(event->GetInnerEventId()), event);
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestCallHangupTest --> OnRequestCallHangupTest "
            "finished");
    }
}

void TelRilTest::OnRequestCallAnswerTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_ACCEPT_CALL);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestCallAnswerTest -->");
        rilManager_->Answer(event);
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestCallAnswerTest --> "
            "OnRequestCallAnswerTest finished");
    }
}

void TelRilTest::OnRequestCallHoldTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_HOLD_CALL);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestCallHoldTest -->");
        rilManager_->Hold(event);
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestCallHoldTest --> "
            "OnRequestCallHoldTest finished");
    }
}

void TelRilTest::OnRequestCallActiveTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_ACTIVE_CALL);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestCallActiveTest -->");
        rilManager_->Active(event);
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestCallActiveTest --> "
            "OnRequestCallActiveTest finished");
    }
}

void TelRilTest::OnRequestCallSwapTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SWAP_CALL);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestCallSwapTest -->");
        rilManager_->Swap(event);
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestCallSwapTest --> "
            "OnRequestCallSwapTest finished");
    }
}

void TelRilTest::OnRequestNetworkVoiceRegistrationStateTest(
    const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(TYPE);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestNetworkVoiceRegistrationStateTest -->");
        rilManager_->GetCsRegStatus(event);
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestNetworkVoiceRegistrationStateTest --> "
            "OnRequestNetworkVoiceRegistrationStateTest finished");
    }
}

void TelRilTest::OnRequestNetworkDataRegistrationStateTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(MAXCONNSTIME);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestNetworkDataRegistrationStateTest -->");
        rilManager_->GetPsRegStatus(event);
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestNetworkDataRegistrationStateTest --> "
            "OnRequestNetworkDataRegistrationStateTest finished");
    }
}

void TelRilTest::OnRequestNetworkOperatorTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_OPERATOR);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestNetworkOperatorTest -->");
        rilManager_->GetOperatorInfo(event);
        TELEPHONY_LOGD("TelRilTest::OnRequestNetworkOperatorTest --> OnRequestNetworkOperatorTest finished");
    }
}

void TelRilTest::OnRequestSendRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SEND_SMS);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestSendRilCmSmsTest -->");
        rilManager_->SendSms("smscPdu", "pdu", event);
        TELEPHONY_LOGD("TelRilTest::OnRequestSendRilCmSmsTest --> OnRequestSendRilCmSmsTest finished");
    }
}

void TelRilTest::OnRequestStorageRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_STORAGE_SMS);
    int32_t status = 0;
    string smsc = GEEERIC_STRING;
    string pdu = GEEERIC_STRING;
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestStorageRilCmSmsTest -->");
        rilManager_->StorageSms(status, smsc, pdu, event);
        TELEPHONY_LOGD("TelRilTest::OnRequestStorageRilCmSmsTest --> OnRequestStorageRilCmSmsTest finished");
    }
}

void TelRilTest::OnRequestDeleteRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_DELETE_SMS);
    int32_t gsmIndex = 0;
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestDeleteRilCmSmsTest -->");
        rilManager_->DeleteSms(gsmIndex, event);
        TELEPHONY_LOGD("TelRilTest::OnRequestDeleteRilCmSmsTest --> OnRequestDeleteRilCmSmsTest finished");
    }
}

void TelRilTest::OnRequestUpdateRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_UPDATE_SMS);
    int32_t gsmIndex = 0;
    std::string pdu = GEEERIC_STRING;
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestUpdateRilCmSmsTest -->");
        rilManager_->UpdateSms(gsmIndex, 0, "00", pdu, event);
        TELEPHONY_LOGD("TelRilTest::OnRequestUpdateRilCmSmsTest --> OnRequestUpdateRilCmSmsTest finished");
    }
}

void TelRilTest::OnRequestSetRilCmSmsCenterAddressTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SET_SMS_CENTER_ADDRESS);
    int32_t tosca = 0;
    std::string address = GEEERIC_STRING;
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestSetRilCmSmsCenterAddressTest -->");
        rilManager_->SetSmsCenterAddress(tosca, address, event);
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestSetRilCmSmsCenterAddressTest --> OnRequestSetRilCmSmsCenterAddressTest "
            "finished");
    }
}

void TelRilTest::OnRequestGetRilCmSmsCenterAddressTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_SMS_CENTER_ADDRESS);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestGetRilCmSmsCenterAddressTest -->");
        rilManager_->GetSmsCenterAddress(event);
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestGetRilCmSmsCenterAddressTest --> OnRequestGetRilCmSmsCenterAddressTest "
            "finished");
    }
}

void TelRilTest::OnRequestSetRilCmCellBroadcastTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SET_CELL_BROADCAST);
    int32_t mode = 0;
    std::string idList = GEEERIC_STRING;
    std::string dcsList = GEEERIC_STRING;
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::SetRilCmCellBroadcastTest -->");
        rilManager_->SetCellBroadcast(mode, "0,1,5,320-478,922", "0-3,5", event);
        TELEPHONY_LOGD("TelRilTest::SetRilCmCellBroadcastTest --> SetRilCmCellBroadcastTest finished");
    }
}

void TelRilTest::OnRequestSmsSendSmsExpectMoreTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SEND_SMS_EXPECT_MORE);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestSmsSendSmsExpectMoreTest -->");
        rilManager_->SendSmsMoreMode("smscPdu", "pdu", event);
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestSmsSendSmsExpectMoreTest --> OnRequestSmsSendSmsExpectMoreTest "
            "finished");
    }
}

void TelRilTest::OnRequestSetRadioStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SET_STATUS);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestSetRadioStatusTest -->");
        rilManager_->SetRadioStatus(0, 0, event);
        TELEPHONY_LOGD("TelRilTest::OnRequestSetRadioStatusTest --> OnRequestSetRadioStatusTest finished");
    }
}

void TelRilTest::OnRequestGetRadioStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_STATUS);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestOnGetRadioStatusTest -->");
        rilManager_->GetRadioStatus(event);
        TELEPHONY_LOGD("TelRilTest::OnRequestOnGetRadioStatusTest --> OnRequestOnGetRadioStatusTest finished");
    }
}

void TelRilTest::OnRequestSmsAcknowledgeTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(MAXCONNS);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestSmsAcknowledgeTest -->");
        rilManager_->SendSmsAck(true, REASON, event);
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestSmsAcknowledgeTest -->"
            " OnRequestSmsAcknowledgeTest finished");
    }
}

void TelRilTest::OnRequestDataDisableDataCallTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(TYPESBITMAP);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestCallDeactivateDataCallTest -->");
        rilManager_->DeactivatePdpContext(CID, REASON, event);
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestDataDisableDataCallTest --> "
            "OnRequestDataDisableDataCallTest finished");
    }
}

void TelRilTest::OnRequestGetNetworkSearchInformationTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(TYPESBITMAP);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestGetAvailableNetworkTest -->");
        rilManager_->GetNetworkSearchInformation(event);
        TELEPHONY_LOGD("TelRilTest::OnRequestGetAvailableNetworkTest -->finished");
    }
}

void TelRilTest::OnRequestGetNetworkSelectionModeTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(TYPESBITMAP);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestGetNetworkSelectionModeTest -->");
        rilManager_->GetNetworkSelectionMode(event);
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestGetNetworkSelectionModeTest --> "
            "OnRequestGetNetworkSelectionModeTest finished");
    }
}

void TelRilTest::OnRequestSetNetworkSelectionModeTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(TYPESBITMAP);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestSetNetworkSelectionModeTest -->");
        rilManager_->SetNetworkSelectionMode(0, "46001", event);
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestSetNetworkSelectionModeTest --> "
            "OnRequestSetNetworkSelectionModeTest finished");
    }
}

void TelRilTest::OnRequestSetNetworkLocationUpdateTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(TYPESBITMAP);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestSetNetworkLocationUpdateTest -->");
        rilManager_->SetNetworkLocationUpdate(event);
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestSetNetworkLocationUpdateTest --> "
            "OnRequestSetNetworkLocationUpdateTest finished");
    }
}

void TelRilTest::OnRequestCallJoinTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t callType = 0;
    TELEPHONY_LOGD("RilUnitTest::OnRequestCallJoinTest -->");
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_JOIN_CALL);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestCallJoinTest -->");
        rilManager_->Join(callType, event);
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestCallJoinTest --> "
            "OnRequestCallJoinTest finished");
    }
}

void TelRilTest::OnRequestCallSplitTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t nThCall = 0;
    int32_t callType = 0;
    TELEPHONY_LOGD("RilUnitTest::OnRequestCallSplitTest -->");
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SPLIT_CALL);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestCallSplitTest -->");
        rilManager_->Split(nThCall, callType, event);
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestCallSplitTest --> "
            "OnRequestCallSplitTest finished");
    }
}

void TelRilTest::OnRequestGetCallForwardTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t reason = 0;
    TELEPHONY_LOGD("RilUnitTest::OnRequestGetCallForwardTest -->");
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_CALL_FORWARD);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestGetCallForwardTest -->");
        rilManager_->GetCallForward(reason, event);
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestGetCallForwardTest --> "
            "OnRequestGetCallForwardTest finished");
    }
}

void TelRilTest::OnRequestSetCallForwardTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t mode = 0;
    int32_t reasonType = 0;
    int32_t classx = 0;
    std::string phoneNum = GEEERIC_STRING;
    TELEPHONY_LOGD("RilUnitTest::OnRequestSetCallForwardTest -->");
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SPLIT_CALL);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestSetCallForwardTest -->");
        rilManager_->SetCallForward(reasonType, mode, phoneNum, classx, event);
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestSetCallForwardTest --> "
            "OnRequestSetCallForwardTest finished");
    }
}

void TelRilTest::OnRequestGetClipTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_CALL_CLIP);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestGetClipTest -->");
        rilManager_->GetClip(event);
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestGetClipTest --> "
            "OnRequestGetClipTest finished");
    }
}

void TelRilTest::OnRequestSetClipTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SET_CALL_CLIP);
    if (event != nullptr && rilManager_ != nullptr) {
        int32_t action = 0;
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestSetClipTest -->");
        rilManager_->SetClip(action, event);
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestSetClipTest --> "
            "OnRequestSetClipTest finished");
    }
}

void TelRilTest::OnRequestGetCallRestrictionTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_CALL_RESTRICTION);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestGetCallRestrictionTest -->");
        rilManager_->GetCallRestriction("AI", event);
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestGetCallRestrictionTest --> "
            "OnRequestGetCallRestrictionTest finished");
    }
}

void TelRilTest::OnRequestSetCallRestrictionTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SET_CALL_RESTRICTION);
    if (event != nullptr && rilManager_ != nullptr) {
        int32_t action = 0;
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestSetCallRestrictionTest -->");
        rilManager_->SetClip(action, event);
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestSetCallRestrictionTest --> "
            "OnRequestSetCallRestrictionTest finished");
    }
}

void TelRilTest::OnRequestSendDtmfTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SEND_DTMF);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestSendDtmfTest -->");
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestSendDtmfTest --> "
            "OnRequestSendDtmfTest finished");
    }
}

void TelRilTest::OnRequestStartDtmfTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_START_DTMF);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestStartDtmfTest -->");
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestStartDtmfTest --> "
            "OnRequestStartDtmfTest finished");
    }
}

void TelRilTest::OnRequestStopDtmfTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_STOP_DTMF);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestStopDtmfTest -->");
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestStopDtmfTest --> "
            "OnRequestStopDtmfTest finished");
    }
}

void TelRilTest::DemoHandler::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto eventId = event->GetInnerEventId();
    if (event != nullptr) {
        TELEPHONY_LOGD("TelRilTest::DemoHandler::ProcessEvent --> eventId:%{public}d", eventId);
    }
}

HWTEST_F(TelRilTest, Telephony_TelRil_ALLAPi_0101, Function | MediumTest | Level3)
{
    shared_ptr<AppExecFwk::EventRunner> eventRunner;
    shared_ptr<TelRilTest::DemoHandler> demohandler;
    TELEPHONY_LOGD("TelRilTest::main function entry -->");
    OnInitInterface();
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("ERROR : make_shared<IRilManager>(rilManager) --> nullptr !!!");
        return;
    }
    TELEPHONY_LOGD("make_shared<IRilManager>(rilManager) --> success");
    eventRunner = AppExecFwk::EventRunner::Create("DemoHandler");
    if (eventRunner == nullptr) {
        TELEPHONY_LOGE("ERROR : AppExecFwk::EventRunner::Create(\"DemoHandler\") --> nullptr !!!");
        return;
    }
    TELEPHONY_LOGD("AppExecFwk::EventRunner::Create(\"DemoHandler\") --> success");
    demohandler = make_shared<TelRilTest::DemoHandler>(eventRunner);
    if (demohandler == nullptr) {
        TELEPHONY_LOGE("ERROR : make_shared<TelRilTest::DemoHandler>(runner) --> nullptr !!!");
        return;
    }
    TELEPHONY_LOGD("make_shared<TelRilTest::DemoHandler>(runner) --> success");
    OnInitForRegister(demohandler);
    TELEPHONY_LOGD("OnInitForRegister(g_handler) finished -->");
    eventRunner->Run();
    OnProcessTest(demohandler);
    return;
}
} // namespace Telephony
} // namespace OHOS