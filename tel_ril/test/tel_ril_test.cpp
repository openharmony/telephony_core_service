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
#include <cstdio>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include "phone_manager.h"
#include "i_tel_ril_manager.h"
#include "telephony_log_wrapper.h"

enum DiffInterfaceId {
    TEST_ICC_RILCM_IO_FOR_APP_TEST = 1,
    TEST_GET_RILCM_IMSI_FOR_APP_TEST = 2,
    TEST_GET_RILCM_ICC_CARD_STATUS_TEST = 3,
    TEST_SET_RILCM_CELL_INFO_LIST_RATE_TEST = 4,
    TEST_SET_RILCM_INITIAL_ATTACH_APN_TEST = 5,
    TEST_SET_RILCM_DATA_PROFILE_TEST = 6,
    TEST_GET_RILCM_VOICE_REGISTRATION_STATE_TEST = 7,
    TEST_GET_RILCM_DATA_REGISTRATION_STATE_TEST = 8,
    TEST_ACKNOWLEDGE_RILCM_LAST_INCOMING_GSM_SMS_TEST = 9,
    TEST_SETUP_RILCM_DATA_CALL_TEST = 10,
    TEST_DEACTIVATE_RILCM_DATA_CALL_TEST = 11,
    TEST_SET_BASE_DATA_ALLOWED_TEST = 12,
    TEST_GET_SIGNAL_STRENGTH = 13,
    TEST_HANDUP_CONNECT = 14,
    TEST_ACCEPT_CALL = 15,
    TEST_RADIO_LAST_CALL_FAIL_CAUSE = 16,
    TEST_CURRENT_CALLS = 17,
    TEST_REJECT_CALL = 18,
    TEST_SEND_IMS_GSM_SMS = 19,
    TEST_SEND_SMS = 20,
    TEST_SEND_SMS_EXPECT_MORE = 21,
    TEST_POWER = 22,
    TEST_OPERATOR = 23,
};

using namespace OHOS;
using namespace std;

namespace {
class TelRilTest {
public:
    TelRilTest();

    ~TelRilTest();

    IRilManager *rilManager_ = nullptr;

    void OnInitInterface();

    void OnInitForRegister(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnProcessInput(int32_t what, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallGetCurrentCallsStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSimIccIoTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSimGetImsiTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestNetworkGetRssiTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSimGetSimStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestRefusedCallTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallHangupTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallAnswerTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestNetworkVoiceRegistrationStateTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestNetworkDataRegistrationStateTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestNetworkOperatorTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void SendRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSmsSendSmsExpectMoreTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void SetModemRadioPowerTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSmsAcknowledgeTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestDataSetupDataCallTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestDataDisableDataCallTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

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
    const int FILEID = 28486;
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
    TELEPHONY_LOGI("TelRilTest -->");
    memberFuncMap_[TEST_CURRENT_CALLS] = &TelRilTest::OnRequestCallGetCurrentCallsStatusTest;
}

TelRilTest::~TelRilTest()
{
    TELEPHONY_LOGI("~TelRilTest -->");
}

void TelRilTest::OnInitInterface()
{
    PhoneManager ::GetInstance().Init();
    rilManager_ = PhoneManager ::GetInstance().phone_[1]->rilManager_;
    memberFuncMap_[TEST_GET_SIGNAL_STRENGTH] = &TelRilTest::OnRequestNetworkGetRssiTest;
    memberFuncMap_[TEST_REJECT_CALL] = &TelRilTest::OnRequestRefusedCallTest;
    memberFuncMap_[TEST_HANDUP_CONNECT] = &TelRilTest::OnRequestCallHangupTest;
    memberFuncMap_[TEST_ACCEPT_CALL] = &TelRilTest::OnRequestCallAnswerTest;
    memberFuncMap_[TEST_OPERATOR] = &TelRilTest::OnRequestNetworkOperatorTest;
    memberFuncMap_[TEST_SEND_SMS] = &TelRilTest::SendRilCmSmsTest;
    memberFuncMap_[TEST_SEND_SMS_EXPECT_MORE] = &TelRilTest::OnRequestSmsSendSmsExpectMoreTest;
    memberFuncMap_[TEST_POWER] = &TelRilTest::SetModemRadioPowerTest;
    memberFuncMap_[TEST_ICC_RILCM_IO_FOR_APP_TEST] = &TelRilTest::OnRequestSimIccIoTest;
    memberFuncMap_[TEST_GET_RILCM_IMSI_FOR_APP_TEST] = &TelRilTest::OnRequestSimGetImsiTest;
    memberFuncMap_[TEST_GET_RILCM_ICC_CARD_STATUS_TEST] = &TelRilTest::OnRequestSimGetSimStatusTest;
    memberFuncMap_[TEST_GET_RILCM_VOICE_REGISTRATION_STATE_TEST] =
        &TelRilTest::OnRequestNetworkVoiceRegistrationStateTest;
    memberFuncMap_[TEST_GET_RILCM_DATA_REGISTRATION_STATE_TEST] =
        &TelRilTest::OnRequestNetworkDataRegistrationStateTest;
    memberFuncMap_[TEST_ACKNOWLEDGE_RILCM_LAST_INCOMING_GSM_SMS_TEST] = &TelRilTest::OnRequestSmsAcknowledgeTest;
    memberFuncMap_[TEST_SETUP_RILCM_DATA_CALL_TEST] = &TelRilTest::OnRequestDataSetupDataCallTest;
    memberFuncMap_[TEST_DEACTIVATE_RILCM_DATA_CALL_TEST] = &TelRilTest::OnRequestDataDisableDataCallTest;
}

void TelRilTest::OnInitForRegister(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    TELEPHONY_LOGI("TelRilTest::OnInitForRegister -->");
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
        TELEPHONY_LOGI("TelRilTest::OnRequestCallGetCurrentCallsStatusTest -->");
        rilManager_->GetCallList(event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestCallGetCurrentCallsStatusTest --> "
            "OnRequestCallGetCurrentCallsStatusTest "
            "finished");
    }
}

void TelRilTest::OnRequestSimIccIoTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(CID);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestSimIccIoTest -->");
        rilManager_->ReadIccFile(COMMAND, FILEID, "3F007F20", 0, 0, P3, "", "", "", event);
        TELEPHONY_LOGI("TelRilTest::OnRequestSimIccIoTest --> OnRequestSimIccIoTest finished");
    }
}

void TelRilTest::OnRequestSimGetImsiTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(REASON);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestSimGetImsiTest -->");
        rilManager_->GetImsi("GetImsi", event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestSimGetImsiTest --> "
            "OnRequestSimGetImsiTest finished");
    }
}

void TelRilTest::OnRequestNetworkGetRssiTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_SIGNAL_STRENGTH);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestNetworkGetRssiTest -->");
        rilManager_->GetSignalStrength(event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestNetworkGetRssiTest --> "
            "OnRequestNetworkGetRssiTest finished");
    }
}

void TelRilTest::OnRequestSimGetSimStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(EVENT_3);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestSimGetSimStatusTest -->");
        rilManager_->GetSimStatus(event);
        TELEPHONY_LOGI("TelRilTest::OnRequestSimGetSimStatusTest --> OnRequestSimGetSimStatusTest finished");
    }
}

void TelRilTest::OnRequestRefusedCallTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_REJECT_CALL);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestRefusedCallTest -->");
        rilManager_->Reject(event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestRefusedCallTest --> "
            "OnRequestRefusedCallTest finished");
    }
}

void TelRilTest::OnRequestCallHangupTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_HANDUP_CONNECT);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestCallHangupTest -->");
        rilManager_->Hangup(static_cast<int>(event->GetInnerEventId()), event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestCallHangupTest --> OnRequestCallHangupTest "
            "finished");
    }
}

void TelRilTest::OnRequestCallAnswerTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_ACCEPT_CALL);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestCallAnswerTest -->");
        rilManager_->Answer(event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestCallAnswerTest --> "
            "OnRequestCallAnswerTest finished");
    }
}

void TelRilTest::OnRequestNetworkVoiceRegistrationStateTest(
    const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(TYPE);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestNetworkVoiceRegistrationStateTest -->");
        rilManager_->GetCsRegStatus(event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestNetworkVoiceRegistrationStateTest --> "
            "OnRequestNetworkVoiceRegistrationStateTest finished");
    }
}

void TelRilTest::OnRequestNetworkDataRegistrationStateTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(MAXCONNSTIME);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestNetworkDataRegistrationStateTest -->");
        rilManager_->GetPsRegStatus(event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestNetworkDataRegistrationStateTest --> "
            "OnRequestNetworkDataRegistrationStateTest finished");
    }
}

void TelRilTest::OnRequestNetworkOperatorTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_OPERATOR);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestNetworkOperatorTest -->");
        rilManager_->GetOperatorInfo(event);
        TELEPHONY_LOGI("TelRilTest::OnRequestNetworkOperatorTest --> OnRequestNetworkOperatorTest finished");
    }
}

void TelRilTest::SendRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SEND_SMS);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SendRilCmSmsTest -->");
        rilManager_->SendSms("smscPdu", "pdu", event);
        TELEPHONY_LOGI("TelRilTest::SendRilCmSmsTest --> SendRilCmSmsTest finished");
    }
}

void TelRilTest::OnRequestSmsSendSmsExpectMoreTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SEND_SMS_EXPECT_MORE);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestSmsSendSmsExpectMoreTest -->");
        rilManager_->SendSmsMoreMode("smscPdu", "pdu", event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestSmsSendSmsExpectMoreTest --> OnRequestSmsSendSmsExpectMoreTest "
            "finished");
    }
}

void TelRilTest::SetModemRadioPowerTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_POWER);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SetModemRadioPowerTest -->");
        rilManager_->SetModemRadioPower(true, event);
        TELEPHONY_LOGI("TelRilTest::SetModemRadioPowerTest --> SetModemRadioPowerTest finished");
    }
}

void TelRilTest::OnRequestSmsAcknowledgeTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(MAXCONNS);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestSmsAcknowledgeTest -->");
        rilManager_->SendSmsAck(true, REASON, event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestSmsAcknowledgeTest -->"
            " OnRequestSmsAcknowledgeTest finished");
    }
}

void TelRilTest::OnRequestDataSetupDataCallTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(EVENT_11);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestCallSetupDataCallTest -->");
        CellularDataProfile dataProfile(0, "cmnet", "IPV4V6", AUTHTYPE_1, "", "", "IPV4V6");
        rilManager_->ActivatePdpContext(REASON, dataProfile, false, true, event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestDataSetupDataCallTest -->"
            "OnRequestDataSetupDataCallTest finished");
    }
}

void TelRilTest::OnRequestDataDisableDataCallTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(TYPESBITMAP);
    if (event != nullptr && rilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestCallDeactivateDataCallTest -->");
        rilManager_->DeactivatePdpContext(CID, REASON, event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestDataDisableDataCallTest --> "
            "OnRequestDataDisableDataCallTest finished");
    }
}

void TelRilTest::DemoHandler::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto eventId = event->GetInnerEventId();
    if (event != nullptr) {
        TELEPHONY_LOGI("TelRilTest::DemoHandler::ProcessEvent --> eventId:%{public}d", eventId);
    }
}

void Promote()
{
    cout << "usage:please input a cmd num:" << endl;
    cout << "1 --> OnRequestSimIccIoTest"
         << endl; // failed, send wrong argument to request interface, radioResponseInfo->error : 2
    cout << "2 --> OnRequestSimGetImsiTest" << endl; // pass
    cout << "3 --> OnRequestSimGetSimStatusTest" << endl; // pass
    cout << "7 --> OnRequestNetworkVoiceRegistrationStateTest" << endl; // pass
    cout << "8 --> OnRequestNetworkDataRegistrationStateTest" << endl; // pass
    cout << "9 --> OnRequestSmsAcknowledgeTest" << endl; // failed, response interface isn't yet implemented
    cout << "10 --> OnRequestDataSetupDataCallTest"
         << endl; // failed, send wrong argument to request interface, radioResponseInfo->error : 2
    cout << "11 --> OnRequestDataDisableDataCallTest" << endl; // pass
    cout << "13 --> OnRequestNetworkGetRssiTest" << endl; // failed, Sim not inserted, radioResponseInfo->error : 2
    cout << "14 --> OnRequestCallHangupTest" << endl; // pass
    cout << "15 --> OnRequestCallAnswerTest" << endl; // pass
    cout << "17 --> OnRequestCallGetCurrentCallsStatusTest" << endl; // failed, need to update response interface
    cout << "18 --> OnRequestRefusedCallTest" << endl;
    cout << "19 --> OnRequestSmsSendSmsByImsTest" << endl; // failed, radioResponseInfo->error : 44
    cout << "20 --> SendRilCmSmsTest" << endl; // failed, Sim not inserted, radioResponseInfo->error : 2
    cout << "21 --> OnRequestSmsSendSmsExpectMoreTest"
         << endl; // failed, Sim not inserted, radioResponseInfo->error : 2
    cout << "22 --> SetModemRadioPowerTest" << endl; // pass
    cout << "23 --> OnRequestNetworkOperatorTest"
         << endl; // failed, Invalid response: nullptr, radioResponseInfo->error : 2
}
} // namespace

int main()
{
    std::unique_ptr<TelRilTest> rilManagerAndResponseTest;
    std::shared_ptr<AppExecFwk::EventRunner> eventRunner;
    std::shared_ptr<TelRilTest::DemoHandler> demohandler;
    TELEPHONY_LOGI("TelRilTest::main function entry -->");
    rilManagerAndResponseTest = std::make_unique<TelRilTest>();
    if (rilManagerAndResponseTest != nullptr) {
        rilManagerAndResponseTest->OnInitInterface();
    }
    if (rilManagerAndResponseTest->rilManager_ == nullptr) {
        TELEPHONY_LOGE("ERROR : make_shared<IRilManager>(rilManager) --> nullptr !!!");
        return -1;
    }
    TELEPHONY_LOGI("make_shared<IRilManager>(rilManager) --> success");
    eventRunner = AppExecFwk::EventRunner::Create("DemoHandler");
    if (eventRunner == nullptr) {
        TELEPHONY_LOGE("ERROR : AppExecFwk::EventRunner::Create(\"DemoHandler\") --> nullptr !!!");
        return -1;
    }
    TELEPHONY_LOGI("AppExecFwk::EventRunner::Create(\"DemoHandler\") --> success");
    demohandler = make_shared<TelRilTest::DemoHandler>(eventRunner);
    if (demohandler == nullptr) {
        TELEPHONY_LOGE("ERROR : make_shared<TelRilTest::DemoHandler>(runner) --> nullptr !!!");
        return -1;
    }
    TELEPHONY_LOGI("make_shared<TelRilTest::DemoHandler>(runner) --> success");
    rilManagerAndResponseTest->OnInitForRegister(demohandler);
    TELEPHONY_LOGI("OnInitForRegister(g_handler) finished -->");
    eventRunner->Run();
    int32_t what = 1;
    while (what) {
        Promote();
        cin >> what;
        rilManagerAndResponseTest->OnProcessInput(what, demohandler);
    }
    return 0;
}
