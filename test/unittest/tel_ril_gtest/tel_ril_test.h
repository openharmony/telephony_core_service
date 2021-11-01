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

#ifndef OHOS_TEL_RIL_TEST_H
#define OHOS_TEL_RIL_TEST_H

#include <gtest/gtest.h>

#include "core.h"
#include "core_service_proxy.h"

namespace OHOS {
namespace Telephony {
using namespace std;
enum class DiffInterfaceId {
    TEST_GET_RILCM_ICC_CARD_STATUS = 1,
    TEST_ICC_RILCM_IO_FOR_APP,
    TEST_GET_RILCM_IMSI_FOR_APP,
    TEST_GET_ICCID,
    TEST_GET_SIM_LOCK_STATUS,
    TEST_SET_SIM_LOCK,
    TEST_GET_CHANGE_SIM_PASSWD,
    TEST_ENTER_SIM_PIN,
    TEST_UNLOCK_SIM_PIN,
    TEST_GET_PIN_INPUT_TIMES,
    TEST_SET_RILCM_CELL_INFO_LIST_RATE,
    TEST_SET_RILCM_INITIAL_ATTACH_APN,
    TEST_SET_RILCM_DATA_PROFILE,
    TEST_GET_RILCM_VOICE_REGISTRATION_STATE,
    TEST_GET_RILCM_DATA_REGISTRATION_STATE,
    TEST_ACKNOWLEDGE_RILCM_LAST_INCOMING_GSM_SMS,
    TEST_SETUP_RILCM_DATA_CALL,

    TEST_DEACTIVATE_RILCM_DATA_CALL,
    TEST_SET_BASE_DATA_ALLOWED,
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
    TEST_EXIT
};

class TelRilTest : public testing::Test {
public:
    TelRilTest();
    ~TelRilTest();
    // execute before first testcase
    static void SetUpTestCase();
    void SetUp();
    void TearDown();
    static void TearDownTestCase();

    std::shared_ptr<Telephony::IRilManager> rilManager_ = nullptr;

    void OnInitInterface();

    void OnInitCall();

    void OnInitSms();

    void OnInitSim();

    void OnInitNetwork();

    void OnInitForRegister(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnProcessTest(int32_t index, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallGetCurrentCallsStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSimGetSimStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSimIccIoTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSimGetImsiTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSimGetIccIDTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetSimLockStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetSimLockTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestChangeSimPasswordTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

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

    void OnRequestDataDisableDataCallTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetNetworkSearchInformationTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetNetworkSelectionModeTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestSetNetworkSelectionModeTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestSetNetworkLocationUpdateTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    int32_t GetRandNum();
    std::string GetRandPhoneNum(const int len);

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
    map<DiffInterfaceId, RilManagerAndResponseTestFun> memberFuncMap_;
};
} // namespace Telephony
} // namespace OHOS

#endif