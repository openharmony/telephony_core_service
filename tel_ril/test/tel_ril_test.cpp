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

#include <iostream>
#include "telephony_log_wrapper.h"
#include "core_manager.h"

namespace OHOS {
namespace Telephony {
enum DiffInterfaceId {
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

using namespace OHOS;
using namespace OHOS::Telephony;
using namespace std;

namespace {
class TelRilTest {
public:
    TelRilTest();

    ~TelRilTest();

    std::shared_ptr<IRilManager> rilManager_ = nullptr;

    void OnInitInterface();

    void OnInitCall();

    void OnInitSms();

    void OnInitSim();

    void OnInitNetwork();

    void OnInitForRegister(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnProcessInput(int32_t what, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallGetCurrentCallsStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSimGetSimStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSimIccIoTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSimGetImsiTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSimGetIccIDTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetSimLockStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetSimLockTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestChangeSimPasswordTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestEnterSimPinTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestUnlockSimPinTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetSimPinInputTimesTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestNetworkGetRssiTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestRefusedCallTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetCallWaitTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetCallWaitTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallHangupTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallJoinTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallSplitTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallAnswerTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallHoldTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallDialTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallActiveTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallSwapTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetClipTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSendDtmfTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestStartDtmfTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestStopDtmfTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetClipTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetCallRestrictionTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetCallRestrictionTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestNetworkVoiceRegistrationStateTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestNetworkDataRegistrationStateTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetCallForwardTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetCallForwardTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestNetworkOperatorTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSendRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestStorageRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestDeleteRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestUpdateRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetRilCmSmsCenterAddressTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetRilCmSmsCenterAddressTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetRilCmCellBroadcastTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSmsSendSmsExpectMoreTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetRadioStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetRadioStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSmsAcknowledgeTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestDataSetupDataCallTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestDataDisableDataCallTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetNetworkSearchInformationTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetNetworkSelectionModeTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestSetNetworkSelectionModeTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestSetNetworkLocationUpdateTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void SimTest();
    void CallTest();
    void SmsTest();

    const int CID = 1;
    const int REASON = 2;
    const int EVENT_3 = 3;
    const int AUTHTYPE_4 = 4;
    const int EVENT_5 = 5;
    const int EVENT_6 = 6;
    const int TYPE = 7;
    const int MAXCONNSTIME = 8;
    const int MAXCONNS = 9;
    const int WAITTIME = 10;
    const int EVENT_11 = 11;
    const int TYPESBITMAP = 12;
    const int EVENT_13 = 13;
    const int BEARERBITMAP = 14;
    const int P3 = 15;
    const int COMMAND = 192;
    const int FILEID = 20272;
    const int AUTHTYPE_1 = -1;

    class DemoHandler : public AppExecFwk::EventHandler {
    public:
        explicit DemoHandler(const std::shared_ptr<AppExecFwk::EventRunner> &runner)
            : AppExecFwk::EventHandler(runner)
        {}

        ~DemoHandler() {}

        void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event) override;
    };

private:
    using RilManagerAndResponseTestFun = void (TelRilTest::*)(
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    std::map<uint32_t, RilManagerAndResponseTestFun> memberFuncMap_;
};

TelRilTest::TelRilTest()
{
    TELEPHONY_LOGD("TelRilTest -->");
    memberFuncMap_[TEST_CURRENT_CALLS] = &TelRilTest::OnRequestCallGetCurrentCallsStatusTest;
}

TelRilTest::~TelRilTest()
{
    TELEPHONY_LOGD("~TelRilTest -->");
}

void TelRilTest::OnInitInterface()
{
    CoreManager::GetInstance().Init();
    rilManager_ = CoreManager ::GetInstance().getCore(CoreManager::DEFAULT_SLOT_ID)->GetRilManager();

    /* --------------------------------- MODEL ----------------------------- */
    memberFuncMap_[TEST_GET_SIGNAL_STRENGTH] = &TelRilTest::OnRequestNetworkGetRssiTest;
    memberFuncMap_[TEST_SET_POWER_STATE] = &TelRilTest::OnRequestSetRadioStatusTest;
    memberFuncMap_[TEST_GET_POWER_STATE] = &TelRilTest::OnRequestGetRadioStatusTest;

    /* --------------------------------- DATA ----------------------------- */
    memberFuncMap_[TEST_SETUP_RILCM_DATA_CALL_TEST] = &TelRilTest::OnRequestDataSetupDataCallTest;
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
    memberFuncMap_[TEST_ENTER_SIM_PIN_TEST] = &TelRilTest::OnRequestEnterSimPinTest;
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
    TELEPHONY_LOGD("TelRilTest::OnInitForRegister -->");
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

void TelRilTest::OnProcessInput(int32_t what, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto itFunc = memberFuncMap_.find(what);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
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
        std::string fac;

        std::cout << "please enter the fac:";
        std::cin >> fac;

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
        std::string fac;
        int mode;
        std::string passwd;

        std::cout << "please enter the fac:";
        std::cin >> fac;
        std::cout << "please enter the mode:";
        std::cin >> mode;
        std::cout << "please enter the passwd:";
        std::cin >> passwd;

        TELEPHONY_LOGD("TelRilTest::%{public}s -->", __func__);
        rilManager_->SetSimLock(fac, mode, passwd, event);
        TELEPHONY_LOGD("TelRilTest::%{public}s --> finished", __func__);
    }
}

void TelRilTest::OnRequestChangeSimPasswordTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_CHANGE_PASSWD);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        std::string fac;
        std::string oldPassword;
        std::string newPassword;
        int32_t passwordLength = 4;

        std::cout << "please enter the fac:";
        std::cin >> fac;
        std::cout << "please enter the oldPassword:";
        std::cin >> oldPassword;
        std::cout << "please enter the newPassword:";
        std::cin >> newPassword;

        TELEPHONY_LOGD("TelRilTest::%{public}s -->", __func__);
        rilManager_->ChangeSimPassword(fac, oldPassword, newPassword, passwordLength, event);
        TELEPHONY_LOGD("TelRilTest::%{public}s --> finished", __func__);
    }
}

void TelRilTest::OnRequestEnterSimPinTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_ENTER_PIN);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);

        std::string pin;
        std::cout << "please enter the SIM PIN:";
        std::cin >> pin;

        TELEPHONY_LOGD("TelRilTest::%{public}s -->", __func__);
        rilManager_->EnterSimPin(pin, event);
        TELEPHONY_LOGD("TelRilTest::%{public}s --> finished", __func__);
    }
}

void TelRilTest::OnRequestUnlockSimPinTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_UNLOCK_PIN);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        std::string puk;
        std::string pin;

        std::cout << "please enter the SIM PUK:";
        std::cin >> puk;
        std::cout << "please enter the SIM PIN:";
        std::cin >> pin;

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

    std::string phoneNum;
    int32_t clirMode; /* Calling Line Identification Restriction . From TS 27.007 V3.4.0 (2000-03) */
    event->SetOwner(handler);
    std::cout << "please enter the phone number:";
    std::cin >> phoneNum;
    clirMode = 0; // use subscription default value
    TELEPHONY_LOGD("TelRilTest::OnRequestCallDialTest -->");
    rilManager_->Dial(phoneNum, clirMode, event);
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
    int32_t operating;

    TELEPHONY_LOGD("TelRilTest::OnRequestSetCallWaitTest -->");
    std::cout << "Please input set value[0:disable 1:enable]: " << endl;
    std::cin >> operating;
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
    int32_t status;
    std::cout << "Please input status:" << std::endl;
    std::cin >> status;
    std::cout << "Please input smsc:" << std::endl;
    string smsc;
    std::cin >> smsc;
    std::cout << "Please input pdu:" << std::endl;
    string pdu;
    std::cin >> pdu;
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
    int32_t gsmIndex;

    std::cout << "Please input gsmIndex: " << endl;
    std::cin >> gsmIndex;
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
    int32_t gsmIndex;
    std::string pdu;

    std::cout << "Please input gsmIndex: " << endl;
    std::cin >> gsmIndex;
    std::cout << "Please input pdu: " << endl;
    std::cin >> pdu;
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
    int32_t tosca;
    std::string address;

    std::cout << "Please input tosca: " << endl;
    std::cin >> tosca;
    std::cout << "Please input address: " << endl;
    std::cin >> address;
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
    int32_t mode;
    std::string idList;
    std::string dcsList;

    std::cout << "Please input mode: " << endl;
    std::cin >> mode;
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
        int radioStatus = -1;

        std::cout << "please enter the new radioStatus:";
        std::cin >> radioStatus;

        rilManager_->SetRadioStatus(radioStatus, 0, event);
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

void TelRilTest::OnRequestDataSetupDataCallTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(EVENT_11);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestCallSetupDataCallTest -->");
        CellularDataProfile dataProfile(0, "cmnet", "IPV4V6", AUTHTYPE_1, "", "", "IPV4V6");
        rilManager_->ActivatePdpContext(REASON, dataProfile, false, true, event);
        TELEPHONY_LOGD(
            "TelRilTest::OnRequestDataSetupDataCallTest -->"
            "OnRequestDataSetupDataCallTest finished");
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
        TELEPHONY_LOGD("TelRilTest::OnRequestGetAvailableNetworksTest -->");
        rilManager_->GetNetworkSearchInformation(event);
        TELEPHONY_LOGD("TelRilTest::OnRequestGetAvailableNetworksTest -->finished");
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
        rilManager_->SetNetworkSelectionMode(1, "46001", event);
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
    int32_t callType; /* call type
                       * 0: Voice call
                       * 1: Video call: send one-way video, two-way voice
                       * 2: Video call: one-way receiving video, two-way voice
                       * 3: Video call: two-way video, two-way voice
                       */

    TELEPHONY_LOGD("RilUnitTest::OnRequestCallJoinTest -->");
    std::cout << "please enter the call type:";
    std::cin >> callType;

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
    int32_t nThCall;
    int32_t callType; /* call type
                       * 0: Voice call
                       * 1: Video call: send one-way video, two-way voice
                       * 2: Video call: one-way receiving video, two-way voice
                       * 3: Video call: two-way video, two-way voice
                       */

    TELEPHONY_LOGD("RilUnitTest::OnRequestCallSplitTest -->");

    std::cout << "please enter the call split number:";
    std::cin >> nThCall;

    std::cout << "please enter the call type:";
    std::cin >> callType;

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
    int32_t reason;

    TELEPHONY_LOGD("RilUnitTest::OnRequestGetCallForwardTest -->");

    std::cout << "please enter Get Call Forward reason<0-5>:";
    std::cin >> reason;

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

void DiffParamType(int32_t loopFlag, int32_t reasonType)
{
    const int32_t MIN_TYPE = 0;
    const int32_t MAX_TYPE = 4;
    while (loopFlag) {
        cout << "0: unconditional" << endl;
        cout << "1: mobile busy" << endl;
        cout << "2: no reply" << endl;
        cout << "3: not reachable" << endl;
        cout << "4: all call forwarding" << endl;
        cout << "5: all conditional call forwarding" << endl;
        std::cout << "please select call forward reason type: ";
        std::cin >> reasonType;
        if (reasonType < MIN_TYPE || reasonType > MAX_TYPE) {
            std::cout << "select error, please retry!" << endl;
            continue;
        }
        break;
    }
}

void DiffParamMode(int32_t loopFlag, int32_t mode)
{
    const int32_t MIN_MODE = 0;
    const int32_t MAX_MODE = 4;
    const int32_t QUERY_STATUS = 2;
    while (loopFlag) {
        cout << "0: disable" << endl;
        cout << "1: enable" << endl; //  "2: query status"
        cout << "3: registration" << endl;
        cout << "4: erasure" << endl;
        std::cout << "please select call forward mode type: ";
        std::cin >> mode;
        if (mode < MIN_MODE || mode > MAX_MODE) {
            std::cout << "select error, please retry!" << endl;
            continue;
        }
        if (mode == QUERY_STATUS) {
            std::cout << "select error, mode 2 is query status please retry!" << endl;
            continue;
        }
        break;
    }
}

void DiffParamClassx(int32_t loopFlag, int32_t classx)
{
    const int32_t MIN_CLASSX = 1;
    const int32_t MAX_CLASSX = 16;
    while (loopFlag) {
        cout << "1: voice" << endl;
        cout << "2: data" << endl;
        cout << "4: fax" << endl;
        cout << "8: short message service" << endl;
        cout << "16: data circuit sync" << endl;
        std::cout << "please select call forward class type: ";
        std::cin >> classx;
        if (classx < MIN_CLASSX || classx > MAX_CLASSX) {
            std::cout << "select error, please retry!" << endl;
            continue;
        }
        break;
    }
}

void TelRilTest::OnRequestSetCallForwardTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t mode = 0;
    int32_t reasonType = 0;
    int32_t classx = 0; /* call type
                         * 0: Voice call
                         * 1: Video call: send one-way video, two-way voice
                         * 2: Video call: one-way receiving video, two-way voice
                         * 3: Video call: two-way video, two-way voice
                         */
    std::string phoneNum;
    int32_t loopFlag = true;

    TELEPHONY_LOGD("RilUnitTest::OnRequestSetCallForwardTest -->");
    DiffParamType(loopFlag, reasonType);
    DiffParamMode(loopFlag, mode);

    std::cout << "please enter the phone number:";
    std::cin >> phoneNum;

    DiffParamClassx(loopFlag, classx);

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
    TELEPHONY_LOGI("RilUnitTest::OnRequestGetClipTest -->");

    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_CALL_CLIP);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestGetClipTest -->");
        rilManager_->GetClip(event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestGetClipTest --> "
            "OnRequestGetClipTest finished");
    }
}

void TelRilTest::OnRequestSetClipTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SET_CALL_CLIP);
    if (event != nullptr && rilManager_ != nullptr) {
        int32_t action;
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestSetClipTest -->");
        std::cout << "please input call set clip action: ";
        std::cin >> action;
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
        int32_t action;
        event->SetOwner(handler);
        TELEPHONY_LOGD("TelRilTest::OnRequestSetCallRestrictionTest -->");
        std::cout << "please input call set clir action: ";
        std::cin >> action;
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

void Promote()
{
    cout << "########################### TEL RIL TEST ######################" << endl;
    cout << "usage:" << endl;

    cout << TEST_SET_POWER_STATE << " --> OnRequestSetRadioStatusTest" << endl;
    cout << TEST_GET_POWER_STATE << " --> OnRequestGetRadioStatusTest" << endl;

    cout << TEST_EXIT << "--> Exit" << endl << endl; // exit
    cout << "please input a cmd num: ";
}

void SimTest()
{
    /*-----------------------------------------------SIM-------------------------------------*/
    cout << TEST_GET_RILCM_ICC_CARD_STATUS_TEST << "--> OnRequestSimGetSimStatusTest" << endl; // pass
    cout << TEST_ICC_RILCM_IO_FOR_APP_TEST << "--> OnRequestSimIccIoTest" << endl;
    cout << TEST_GET_RILCM_IMSI_FOR_APP_TEST << "--> OnRequestSimGetImsiTest" << endl; // pass
    cout << TEST_GET_ICCID_TEST << "--> OnRequestSimGetIccIDTest" << endl; // pass
    cout << TEST_GET_SIM_LOCK_STATUS_TEST << "--> OnRequestGetSimLockStatusTest" << endl; // pass
    cout << TEST_SET_SIM_LOCK_TEST << "--> OnRequestSetSimLockTest" << endl; // pass
    cout << TEST_GET_CHANGE_SIM_PASSWD_TEST << "--> OnRequestChangeSimPasswordTest" << endl; // pass
    cout << TEST_ENTER_SIM_PIN_TEST << "--> OnRequestEnterSimPinTest" << endl; // pass
    cout << TEST_UNLOCK_SIM_PIN_TEST << "--> OnRequestUnlockSimPinTest" << endl; // pass
    cout << TEST_GET_PIN_INPUT_TIMES_TEST << "--> OnRequestGetSimPinInputTimesTest" << endl; // pass

    cout << TEST_SETUP_RILCM_DATA_CALL_TEST << "--> OnRequestDataSetupDataCallTest" << endl;
    cout << TEST_DEACTIVATE_RILCM_DATA_CALL_TEST << "--> OnRequestDataDisableDataCallTest" << endl; // pass
    cout << TEST_ACKNOWLEDGE_RILCM_LAST_INCOMING_GSM_SMS_TEST << "--> OnRequestSmsAcknowledgeTest" << endl;
    cout << TEST_GET_SIGNAL_STRENGTH << "--> OnRequestNetworkGetRssiTest" << endl;
}

void CallTest()
{
    /* --------------------------------- CALL -------------------------- */
    cout << TEST_CALL_DIAL << " --> OnRequestCallDialTest" << endl;
    cout << TEST_HANDUP_CONNECT << " --> OnRequestCallHangupTest" << endl;
    cout << TEST_ACCEPT_CALL << "--> OnRequestCallAnswerTest" << endl;
    cout << TEST_CURRENT_CALLS << "--> OnRequestCallGetCurrentCallsStatusTest" << endl;
    cout << TEST_REJECT_CALL << "--> OnRequestRefusedCallTest" << endl;
    cout << TEST_JOIN_CALL << "--> OnRequestCallJoinTest" << endl;
    cout << TEST_SPLIT_CALL << "--> OnRequestCallSplitTest" << endl;
    cout << TEST_GET_CALL_WAIT << " --> OnRequestGetCallWaitTest" << endl;
    cout << TEST_SET_CALL_WAIT << " --> OnRequestSetCallWaitTest" << endl;
    cout << TEST_GET_CALL_FORWARD << " --> OnRequestGetCallForwardTest" << endl;
    cout << TEST_SET_CALL_FORWARD << " --> OnRequestSetCallForwardTest" << endl;
    cout << TEST_GET_CALL_DEAL_CLIP << " --> OnRequestGetClipTest" << endl;
    cout << TEST_SET_CALL_CLIP << " --> OnRequestSetClipTest" << endl;
    cout << TEST_GET_CALL_RESTRICTION << " --> OnRequestGetCallRestrictionTest" << endl;
    cout << TEST_SET_CALL_RESTRICTION << " --> OnRequestSetCallRestrictionTest" << endl;
    cout << TEST_SEND_DTMF << " --> OnRequestSendDtmfTest" << endl;
    cout << TEST_START_DTMF << " --> OnRequestStartDtmfTest" << endl;
    cout << TEST_STOP_DTMF << " --> OnRequestStopDtmfTest" << endl;
}

void SmsTest()
{
    /* --------------------------------- SMS -------------------------- */
    cout << "19 --> OnRequestSmsSendSmsByImsTest" << endl; // failed, radioResponseInfo->error : 44
    cout << TEST_SEND_SMS << "--> OnRequestSendRilCmSmsTest"
         << endl; // failed, Sim not inserted, radioResponseInfo->error : 2
    cout << TEST_STORAGE_SMS << "--> OnRequestStorageRilCmSmsTest" << endl;
    cout << TEST_DELETE_SMS << "--> OnRequestDeleteRilCmSmsTest" << endl;
    cout << TEST_UPDATE_SMS << "--> OnRequestUpdateRilCmSmsTest" << endl;
    cout << TEST_SET_SMS_CENTER_ADDRESS << "--> OnRequestSetRilCmSmsCenterAddressTest" << endl;
    cout << TEST_GET_SMS_CENTER_ADDRESS << "--> OnRequestGetRilCmSmsCenterAddressTest" << endl;
    cout << TEST_SET_CELL_BROADCAST << "--> OnRequestSetRilCmCellBroadcastTest" << endl;
    cout << "21 --> OnRequestSmsSendSmsExpectMoreTest"
         << endl; // failed, Sim not inserted, radioResponseInfo->error : 2
    cout << "22 --> OnRequestSetModemRadioPowerTest" << endl; // pass
    cout << "23 --> OnRequestNetworkOperatorTest"
         << endl; // failed, Invalid response: nullptr, radioResponseInfo->error : 2
    cout << TEST_GET_NETWORKS_TO_USE << "--> OnRequestGetNetworkSearchInformationTest"
         << endl; // failed, Invalid response: nullptr, radioResponseInfo->error : 2
    cout << TEST_GET_SELECTION_MOD_FOR_NETWORKS << "--> OnRequestGetNetworkSelectionModeTest"
         << endl; // failed, Invalid response: nullptr, radioResponseInfo->error : 2
    cout << TEST_SET_MODE_AUTOMATIC_NETWORKS << "--> OnRequestSetNetworkSelectionModeTest"
         << endl; // failed, Invalid response: nullptr, radioResponseInfo->error : 2
    cout << TEST_SET_LOCATION_UPDATE_FOR_NETWORKS << "--> OnRequestSetNetworkLocationUpdateTest"
         << endl; // failed, Invalid response: nullptr, radioResponseInfo->error : 2
    cout << TEST_GET_RILCM_VOICE_REGISTRATION_STATE_TEST << "--> OnRequestNetworkVoiceRegistrationStateTest"
         << endl; // pass
    cout << TEST_GET_RILCM_DATA_REGISTRATION_STATE_TEST << "--> OnRequestNetworkDataRegistrationStateTest"
         << endl; // pass
}
} // namespace
} // namespace Telephony
} // namespace OHOS

using namespace OHOS;
using namespace OHOS::Telephony;
int main()
{
    std::unique_ptr<TelRilTest> rilManagerAndResponseTest;
    std::shared_ptr<AppExecFwk::EventRunner> eventRunner;
    std::shared_ptr<TelRilTest::DemoHandler> demohandler;
    TELEPHONY_LOGD("TelRilTest::main function entry -->");
    rilManagerAndResponseTest = std::make_unique<TelRilTest>();
    if (rilManagerAndResponseTest != nullptr) {
        rilManagerAndResponseTest->OnInitInterface();
    }
    if (rilManagerAndResponseTest->rilManager_ == nullptr) {
        TELEPHONY_LOGE("ERROR : make_shared<IRilManager>(rilManager) --> nullptr !!!");
        return -1;
    }
    TELEPHONY_LOGD("make_shared<IRilManager>(rilManager) --> success");
    eventRunner = AppExecFwk::EventRunner::Create("DemoHandler");
    if (eventRunner == nullptr) {
        TELEPHONY_LOGE("ERROR : AppExecFwk::EventRunner::Create(\"DemoHandler\") --> nullptr !!!");
        return -1;
    }
    TELEPHONY_LOGD("AppExecFwk::EventRunner::Create(\"DemoHandler\") --> success");
    demohandler = make_shared<TelRilTest::DemoHandler>(eventRunner);
    if (demohandler == nullptr) {
        TELEPHONY_LOGE("ERROR : make_shared<TelRilTest::DemoHandler>(runner) --> nullptr !!!");
        return -1;
    }
    TELEPHONY_LOGD("make_shared<TelRilTest::DemoHandler>(runner) --> success");
    rilManagerAndResponseTest->OnInitForRegister(demohandler);
    TELEPHONY_LOGD("OnInitForRegister(g_handler) finished -->");
    eventRunner->Run();
    int32_t what = 1;
    while (what) {
        Promote();
        SimTest();
        CallTest();
        SmsTest();
        cin >> what;
        cout << "" << endl;
        if (what == TEST_EXIT) {
            break; // test end exit
        }
        rilManagerAndResponseTest->OnProcessInput(what, demohandler);
    }
    return 0;
}
